package collectors

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The parser records each selector it models into its own field, keeps the
// set it cannot enumerate as unmodelled, and treats counters and comments as
// inert. The iptables-nft spellings (W-36) are the ones a ufw host dumps.
func TestParseNftRuleRecordsSelectors(t *testing.T) {
	cases := []struct {
		line string
		want fwRule
	}{
		{`iif "lo" accept`, fwRule{Iif: "lo", Action: "accept"}},
		{`ct state established,related accept`, fwRule{Ctstate: "established,related", Action: "accept"}},
		{`ct state { established, related } accept`, fwRule{Ctstate: "established,related", Action: "accept"}},
		{`ip daddr 224.0.0.251 accept`, fwRule{Daddr: "224.0.0.251", Action: "accept"}},
		{`ip6 saddr fe80::/10 accept`, fwRule{Saddr: "fe80::/10", Action: "accept"}},
		{`tcp dport 22 accept`, fwRule{Proto: "tcp", Dport: "22", Action: "accept"}},
		{`tcp dport { 22, 80 } accept`, fwRule{Proto: "tcp", Dport: "{ 22, 80 }", Action: "accept"}},
		{`udp dport 1000-2000 accept`, fwRule{Proto: "udp", Dport: "1000-2000", Action: "accept"}},
		{`tcp dport @ports accept`, fwRule{Proto: "tcp", Dport: "@ports", Action: "accept", Unmodelled: true}},
		{`tcp dport != 22 accept`, fwRule{Proto: "tcp", Action: "accept", Unmodelled: true}},
		{`meta l4proto { tcp, udp } th dport 53 accept`, fwRule{Dport: "53", Action: "accept", Unmodelled: true}},
		{`tcp dport vmap { 22 : accept, 80 : drop }`, fwRule{Proto: "tcp", Unmodelled: true}},
		{`jump ufw-before-input`, fwRule{Action: "jump ufw-before-input"}},
		{`goto filter_IN_public`, fwRule{Action: "goto filter_IN_public"}},
		{`counter packets 0 bytes 0 accept`, fwRule{Action: "accept"}}, // counter is inert
		{`tcp dport 22 accept comment "ssh in"`, fwRule{Proto: "tcp", Dport: "22", Action: "accept"}},
		{`meta mark 0x1 accept`, fwRule{Action: "accept", Unmodelled: true}},
		// A concatenation (W-56) records no selector: the field stays empty.
		{`meta l4proto . th dport { tcp . 22, udp . 53 } accept`, fwRule{Action: "accept", Unmodelled: true}},
		{`meta l4proto . th dport @allowed accept`, fwRule{Action: "accept", Unmodelled: true}},
		{`ip protocol . th dport { tcp . 22 } accept`, fwRule{Action: "accept", Unmodelled: true}},
		{`ct state . tcp dport { new . 22 } accept`, fwRule{Action: "accept", Unmodelled: true}},
		{`ip saddr . tcp dport vmap { 192.0.2.1 . 22 : accept }`, fwRule{Unmodelled: true}},
		// A verdict map (M-1) leaves the field and the action unread.
		{`ct state vmap { established : accept, related : accept, invalid : drop }`, fwRule{Unmodelled: true}},
		// No verdict at all (W-55).
		{`counter packets 0 bytes 0`, fwRule{Action: "none"}},
		{`meta l4proto tcp tcp dport 22 ct state new # recent: SET name: DEFAULT side: source counter packets 0 bytes 0`, fwRule{Proto: "tcp", Dport: "22", Ctstate: "new", Action: "none", Unmodelled: true}},
		{`reject with icmpx type admin-prohibited`, fwRule{Action: "reject"}},
		{`log prefix "Host INPUT Allow host" group 0 accept`, fwRule{Action: "accept"}},
		{`iifname != "lo" accept`, fwRule{Action: "accept", Unmodelled: true}},
		// The iptables-nft spellings ufw's stock chains dump as (W-36).
		{`iifname "lo" counter packets 0 bytes 0 accept`, fwRule{Iif: "lo", Action: "accept"}},
		{`ct state related,established counter packets 0 bytes 0 accept`, fwRule{Ctstate: "related,established", Action: "accept"}},
		{`meta l4proto icmp icmp type destination-unreachable counter packets 0 bytes 0 accept`, fwRule{Proto: "icmp", Action: "accept", Unmodelled: true}},
		{`fib daddr type local counter packets 0 bytes 0 return`, fwRule{Action: "return", Unmodelled: true}},
		{`limit rate 3/minute burst 10 packets counter packets 0 bytes 0 jump ufw-logging-deny`, fwRule{Action: "jump ufw-logging-deny", Unmodelled: true}},
		{`limit rate 3/minute burst 10 packets counter packets 0 bytes 0 log prefix "[UFW BLOCK] "`, fwRule{Action: "log", Unmodelled: true}},
		{`meta l4proto tcp tcp dport 22 counter packets 0 bytes 0 accept`, fwRule{Proto: "tcp", Dport: "22", Action: "accept"}},
		{`meta l4proto udp ip daddr 224.0.0.251 udp dport 5353 counter packets 0 bytes 0 accept`, fwRule{Proto: "udp", Daddr: "224.0.0.251", Dport: "5353", Action: "accept"}},
		{`meta l4proto udp udp sport 67 udp dport 68 counter packets 0 bytes 0 accept`, fwRule{Proto: "udp", Dport: "68", Action: "accept"}},
		// An untranslated xt match iptables-nft prints after a '#'.
		{`meta l4proto tcp tcp dport 30443 # nfacct-name localhost counter packets 0 bytes 0 jump KUBE-EXT-X`, fwRule{Proto: "tcp", Dport: "30443", Action: "jump KUBE-EXT-X", Unmodelled: true}},
	}
	for _, c := range cases {
		got := parseNftRule("INPUT", strings.Fields(c.line))
		if got.Chain != "INPUT" {
			t.Errorf("%q: chain %q, want INPUT", c.line, got.Chain)
		}
		if got.Raw != strings.Join(strings.Fields(c.line), " ") {
			t.Errorf("%q: raw %q", c.line, got.Raw)
		}
		got.Raw, got.Chain = "", ""
		if got != c.want {
			t.Errorf("%q:\n got %+v\nwant %+v", c.line, got, c.want)
		}
	}
}

func TestParseIptablesRuleRecordsSelectors(t *testing.T) {
	cases := []struct {
		line string
		want fwRule
	}{
		{`-A INPUT -i lo -j ACCEPT`, fwRule{Iif: "lo", Action: "accept"}},
		{`-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT`, fwRule{Ctstate: "related,established", Action: "accept"}},
		{`-A INPUT -m state --state NEW -p tcp --dport 22 -j ACCEPT`, fwRule{Ctstate: "new", Proto: "tcp", Dport: "22", Action: "accept"}},
		{`-A INPUT -p tcp -m multiport --dports 22,80,443 -j ACCEPT`, fwRule{Proto: "tcp", Dport: "22,80,443", Action: "accept"}},
		{`-A INPUT -p tcp -m tcp --dport 1000:2000 -j ACCEPT`, fwRule{Proto: "tcp", Dport: "1000:2000", Action: "accept"}},
		{`-A INPUT -d 203.0.113.1/32 -j ACCEPT`, fwRule{Daddr: "203.0.113.1/32", Action: "accept"}},
		{`-A INPUT -s 192.0.2.0/24 -p udp -m udp --sport 67 --dport 68 -j ACCEPT`, fwRule{Saddr: "192.0.2.0/24", Proto: "udp", Dport: "68", Action: "accept"}},
		{`-A INPUT -j ufw-before-input`, fwRule{Action: "jump ufw-before-input"}},
		{`-A INPUT -g ufw-before-input`, fwRule{Action: "goto ufw-before-input"}},
		{`-A INPUT -m owner --uid-owner 0 -j ACCEPT`, fwRule{Action: "accept", Unmodelled: true}},
		{`-A INPUT -p tcp -m comment --comment "allow web in" -m tcp --dport 80 -j ACCEPT`, fwRule{Proto: "tcp", Dport: "80", Action: "accept"}},
		{`-A INPUT ! -i lo -j ACCEPT`, fwRule{Action: "accept", Unmodelled: true}},
		{`-A INPUT -p tcp ! --dport 22 -j ACCEPT`, fwRule{Proto: "tcp", Action: "accept", Unmodelled: true}},
		{`-A INPUT -p tcp --dport ssh -j ACCEPT`, fwRule{Proto: "tcp", Dport: "ssh", Action: "accept", Unmodelled: true}},
		{`-A ufw-user-limit -j REJECT --reject-with icmp-port-unreachable`, fwRule{Action: "reject"}},
		{`-A ufw-after-logging-input -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW BLOCK] "`, fwRule{Action: "log", Unmodelled: true}},
		{`-A ufw-before-input -p icmp -m icmp --icmp-type 3 -j ACCEPT`, fwRule{Proto: "icmp", Action: "accept", Unmodelled: true}},
		{`-A ufw-not-local -m addrtype --dst-type LOCAL -j RETURN`, fwRule{Action: "return", Unmodelled: true}},
		{`-A PREROUTING -j MARK --set-xmark 0x1/0xffffffff`, fwRule{Action: "jump MARK"}},
		{`-A INPUT -j NFQUEUE --queue-num 1`, fwRule{Action: "jump NFQUEUE"}},
		{`-A INPUT -j QUEUE`, fwRule{Action: "queue"}},
		// No target at all (W-55): ufw limit's companion row.
		{`-A ufw-user-input -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name DEFAULT --mask 255.255.255.255 --rsource`, fwRule{Proto: "tcp", Dport: "22", Ctstate: "new", Action: "none", Unmodelled: true}},
		{`-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED,DNAT -j ACCEPT`, fwRule{Ctstate: "related,established,dnat", Action: "accept"}},
	}
	for _, c := range cases {
		f := strings.Fields(c.line)
		got := parseIptablesRule(f[1], f)
		if got.Chain != f[1] {
			t.Errorf("%q: chain %q, want %q", c.line, got.Chain, f[1])
		}
		got.Raw, got.Chain = "", ""
		if got != c.want {
			t.Errorf("%q:\n got %+v\nwant %+v", c.line, got, c.want)
		}
	}
}

// The raw text is the rule as dumped, capped at 512 bytes on a rune boundary.
func TestFwRuleRawIsCapped(t *testing.T) {
	long := "tcp dport 22 comment \"" + strings.Repeat("é", 400) + "\" accept"
	r := parseNftRule("INPUT", strings.Fields(long))
	if len(r.Raw) > fwRawCap || !strings.HasPrefix(long, r.Raw) {
		t.Fatalf("raw is %d bytes (cap %d) or not a prefix of the rule", len(r.Raw), fwRawCap)
	}
	if r.Action != "accept" || r.Dport != "22" {
		t.Errorf("a long comment changed the parse: %+v", r)
	}
}

// v4 builds the key of a chain in the v4 filter table.
func v4(name string) chainKey { return chainKey{Family: "v4", Table: "filter", Name: name} }

var inputV4 = baseChain{name: "INPUT", table: "filter", family: "v4", hook: "input", chainType: "filter", policy: "drop", hasRules: true}

func TestFoldChainsReachesUfwUserInput(t *testing.T) {
	by := map[chainKey][]fwRule{
		v4("INPUT"):            {{Chain: "INPUT", Action: "jump ufw-before-input"}, {Chain: "INPUT", Action: "jump ufw-after-input"}},
		v4("ufw-before-input"): {{Chain: "ufw-before-input", Iif: "lo", Action: "accept"}, {Chain: "ufw-before-input", Action: "jump ufw-user-input"}},
		v4("ufw-user-input"):   {{Chain: "ufw-user-input", Proto: "tcp", Dport: "80", Action: "accept"}},
		v4("ufw-after-input"):  {},
	}
	rows := foldChains([]baseChain{inputV4}, by)
	var depths []int
	for _, r := range rows {
		if r.ViaChain != "INPUT" || r.Family != "v4" {
			t.Errorf("row %+v: via %q family %q, want INPUT v4", r, r.ViaChain, r.Family)
		}
		if r.Dport == "80" {
			depths = append(depths, r.Depth)
			if r.Chain != "ufw-user-input" {
				t.Errorf("the accept's chain is %q", r.Chain)
			}
		}
		if r.Unmodelled {
			t.Errorf("a followed jump or a modelled rule is unmodelled: %+v", r)
		}
	}
	if !slices.Equal(depths, []int{2}) {
		t.Fatalf("depths %v, want [2]", depths)
	}
	if len(rows) != 5 {
		t.Errorf("%d rows, want 5 (2 INPUT + 2 before + 1 user)", len(rows))
	}
}

// A jump the fold followed is not unmodelled, whatever match the parser could
// not model on it: its match only narrows rules that are folded in
// unconditionally (ufw's `limit … jump ufw-logging-deny`).
func TestFoldChainsClearsUnmodelledOnAFollowedJump(t *testing.T) {
	by := map[chainKey][]fwRule{
		v4("INPUT"):            {{Action: "jump ufw-logging-deny", Unmodelled: true}, {Action: "jump ufw-logging-deny", Unmodelled: true}, {Action: "accept", Unmodelled: true}},
		v4("ufw-logging-deny"): {{Action: "log", Unmodelled: true}},
	}
	rows := foldChains([]baseChain{inputV4}, by)
	if len(rows) != 4 {
		t.Fatalf("rows %+v, want 4", rows)
	}
	if rows[0].Unmodelled || rows[2].Unmodelled {
		t.Errorf("followed jumps (first and to a visited chain) stay unmodelled: %+v / %+v", rows[0], rows[2])
	}
	if !rows[1].Unmodelled || !rows[3].Unmodelled {
		t.Errorf("a non-jump row lost its unmodelled flag: %+v / %+v", rows[1], rows[3])
	}
}

// Only a filter base chain on the input hook is folded: a forward chain, a nat
// input chain and a prerouting chain contribute no rows.
func TestFoldChainsFoldsOnlyInputFilterBases(t *testing.T) {
	by := map[chainKey][]fwRule{
		v4("FORWARD"): {{Action: "accept"}},
		{Family: "v4", Table: "nat", Name: "INPUT"}: {{Action: "accept"}},
		v4("PREROUTING"): {{Action: "drop"}},
		v4("INPUT"):      {{Action: "drop"}},
	}
	bases := []baseChain{
		{name: "FORWARD", table: "filter", family: "v4", hook: "forward", chainType: "filter"},
		{name: "INPUT", table: "nat", family: "v4", hook: "input", chainType: "nat"},
		{name: "PREROUTING", table: "filter", family: "v4", hook: "prerouting", chainType: "filter"},
		inputV4,
	}
	rows := foldChains(bases, by)
	if len(rows) != 1 || rows[0].Action != "drop" || rows[0].Depth != 0 || rows[0].Chain != "INPUT" {
		t.Fatalf("rows %+v, want the filter INPUT drop alone", rows)
	}
}

// A jump that would reach depth 5 is not followed: the jump row is unmodelled
// and nothing deeper appears.
func TestFoldChainsStopsAtDepthAndMarksTheJump(t *testing.T) {
	by := map[chainKey][]fwRule{v4("INPUT"): {{Action: "jump c1"}}}
	for i := 1; i <= 6; i++ {
		name := "c" + strconv.Itoa(i)
		by[v4(name)] = []fwRule{{Proto: "tcp", Dport: strconv.Itoa(i), Action: "accept"}, {Action: "jump c" + strconv.Itoa(i+1)}}
	}
	rows := foldChains([]baseChain{inputV4}, by)
	maxDepth := 0
	var cut fwRule
	for _, r := range rows {
		maxDepth = max(maxDepth, r.Depth)
		if r.Action == "jump c5" {
			cut = r
		}
		if r.Dport == "5" || r.Dport == "6" {
			t.Errorf("a rule deeper than 4 jumps was folded: %+v", r)
		}
	}
	if maxDepth != 4 {
		t.Errorf("max depth %d, want 4", maxDepth)
	}
	if !cut.Unmodelled || cut.Depth != 4 || cut.Chain != "c4" {
		t.Errorf("the jump past the depth: %+v, want unmodelled in c4 at depth 4", cut)
	}
	if got := classifyRule(cut); got != "opaque" {
		t.Errorf("the unfollowed jump classifies %q, want opaque", got)
	}
	for _, r := range rows {
		if r.Action != "jump c5" && r.Unmodelled {
			t.Errorf("a followed jump is unmodelled: %+v", r)
		}
	}
	if len(rows) != 9 {
		t.Errorf("%d rows, want 9 (INPUT's jump + two rows of each of c1..c4)", len(rows))
	}
}

func TestFoldChainsVisitsACycleOnce(t *testing.T) {
	by := map[chainKey][]fwRule{
		v4("INPUT"): {{Action: "jump A"}},
		v4("A"):     {{Proto: "tcp", Dport: "22", Action: "accept"}, {Action: "jump B"}},
		v4("B"):     {{Proto: "tcp", Dport: "80", Action: "accept"}, {Action: "jump A"}, {Action: "jump INPUT"}},
	}
	rows := foldChains([]baseChain{inputV4}, by)
	count := map[string]int{}
	for _, r := range rows {
		count[r.Chain]++
		if r.Unmodelled {
			t.Errorf("a jump to a visited chain is unmodelled: %+v", r)
		}
	}
	if count["INPUT"] != 1 || count["A"] != 2 || count["B"] != 3 || len(rows) != 6 {
		t.Fatalf("rows per chain %v, want INPUT 1, A 2, B 3", count)
	}
}

// 2001 rules in a jumped chain: 2000 are folded and the jump row that led to
// the cut chain is unmodelled.
func TestFoldChainsBudget(t *testing.T) {
	big := make([]fwRule, 2001)
	for i := range big {
		big[i] = fwRule{Proto: "tcp", Dport: strconv.Itoa(i + 1), Action: "accept"}
	}
	by := map[chainKey][]fwRule{v4("INPUT"): {{Action: "jump big"}}, v4("big"): big}
	rows := foldChains([]baseChain{inputV4}, by)
	folded := 0
	for _, r := range rows {
		if r.Depth > 0 {
			folded++
		}
	}
	if folded != 2000 {
		t.Errorf("%d folded rows, want 2000", folded)
	}
	if rows[0].Action != "jump big" || !rows[0].Unmodelled {
		t.Errorf("the jump into the cut chain: %+v, want unmodelled", rows[0])
	}
	// The budget is per base chain: a second input base chain folds afresh.
	v6 := baseChain{name: "INPUT", table: "filter", family: "v6", hook: "input", chainType: "filter"}
	by[chainKey{"v6", "filter", "INPUT"}] = []fwRule{{Action: "jump small"}}
	by[chainKey{"v6", "filter", "small"}] = []fwRule{{Action: "accept", Proto: "tcp", Dport: "22"}}
	rows = foldChains([]baseChain{inputV4, v6}, by)
	last := rows[len(rows)-1]
	if last.Family != "v6" || last.Dport != "22" || last.Depth != 1 || last.Unmodelled {
		t.Errorf("the v6 base chain's fold: %+v", last)
	}
}

// A jump whose target is no chain of the base's family and table (an
// extension target such as MARK) is not followed: the row is unmodelled (W-46).
func TestFoldChainsUnknownTargetIsUnmodelled(t *testing.T) {
	by := map[chainKey][]fwRule{v4("INPUT"): {{Action: "jump MARK"}}}
	rows := foldChains([]baseChain{inputV4}, by)
	if len(rows) != 1 || !rows[0].Unmodelled {
		t.Fatalf("rows %+v, want the one jump row unmodelled", rows)
	}
}

// W-33: the same chain names in v4 and v6 stay apart; each family's user
// accept appears once, under its own family.
func TestFoldChainsKeepsFamiliesApart(t *testing.T) {
	v6key := func(n string) chainKey { return chainKey{Family: "v6", Table: "filter", Name: n} }
	by := map[chainKey][]fwRule{
		v4("INPUT"):             {{Action: "jump ufw-user-input"}},
		v4("ufw-user-input"):    {{Proto: "tcp", Dport: "80", Action: "accept"}},
		v6key("INPUT"):          {{Action: "jump ufw-user-input"}},
		v6key("ufw-user-input"): {{Proto: "tcp", Dport: "443", Action: "accept"}},
	}
	v6 := baseChain{name: "INPUT", table: "filter", family: "v6", hook: "input", chainType: "filter"}
	rows := foldChains([]baseChain{inputV4, v6}, by)
	got := map[string]string{}
	for _, r := range rows {
		if r.Dport != "" {
			if _, dup := got[r.Dport]; dup {
				t.Errorf("port %s folded twice", r.Dport)
			}
			got[r.Dport] = r.Family
		}
	}
	if got["80"] != "v4" || got["443"] != "v6" || len(got) != 2 {
		t.Fatalf("ports by family %v, want 80 v4 and 443 v6", got)
	}
}

// nftRows parses nft rule lines into one chain's rows.
func nftRows(lines ...string) []fwRule {
	var out []fwRule
	for _, l := range lines {
		out = append(out, parseNftRule("", strings.Fields(l)))
	}
	return out
}

// iptRows parses iptables-save `-A` lines into rows.
func iptRows(lines ...string) []fwRule {
	var out []fwRule
	for _, l := range lines {
		f := strings.Fields(l)
		out = append(out, parseIptablesRule(f[1], f))
	}
	return out
}

// W-54: a row folded through a jump carries the jump's match. `tcp dport 22
// jump ssh_in` into `ip saddr … accept` is a tcp/22 port rule from that
// source, never an any-port accept.
func TestFoldChainsCarriesTheJumpsMatch(t *testing.T) {
	by := map[chainKey][]fwRule{
		v4("INPUT"):  nftRows(`tcp dport 22 jump ssh_in`, `drop`),
		v4("ssh_in"): nftRows(`ip saddr 192.0.2.0/24 accept`, `drop`),
	}
	rows := foldChains([]baseChain{inputV4}, by)
	if len(rows) != 4 {
		t.Fatalf("rows %+v, want 4", rows)
	}
	acc := rows[1]
	if acc.Chain != "ssh_in" || acc.Proto != "tcp" || acc.Dport != "22" || acc.Saddr != "192.0.2.0/24" || acc.Unmodelled {
		t.Errorf("the folded accept %+v, want tcp/22 from 192.0.2.0/24", acc)
	}
	if got := classifyRule(acc); got != "port_rule" {
		t.Errorf("the folded accept classifies %q, want port_rule", got)
	}
	for _, r := range rows {
		if classifyRule(r) == "any_port" {
			t.Errorf("an any-port row survived the fold: %+v", r)
		}
	}

	// Both set and different: unmodelled. The jump's unmodelled match
	// (here a mark) carries over too.
	by = map[chainKey][]fwRule{
		v4("INPUT"): nftRows(`tcp dport 22 jump a`, `meta mark 0x1 jump b`),
		v4("a"):     nftRows(`tcp dport 80 accept`),
		v4("b"):     nftRows(`accept`),
	}
	rows = foldChains([]baseChain{inputV4}, by)
	if r := rows[1]; r.Dport != "80" || !r.Unmodelled || classifyRule(r) != "opaque" {
		t.Errorf("a conflicting port %+v, want unmodelled (opaque)", r)
	}
	if r := rows[3]; !r.Unmodelled || classifyRule(r) != "opaque" {
		t.Errorf("an accept behind an unmodelled jump %+v, want opaque", r)
	}
	if rows[0].Unmodelled || rows[2].Unmodelled {
		t.Errorf("followed jumps are unmodelled: %+v / %+v", rows[0], rows[2])
	}
}

// Nested jumps accumulate their conditions, and a chain reached under two
// different conditions is folded under each.
func TestFoldChainsAccumulatesNestedConditions(t *testing.T) {
	by := map[chainKey][]fwRule{
		v4("INPUT"): nftRows(`iifname "eth1" jump zone`, `tcp dport 443 jump svc`),
		v4("zone"):  nftRows(`tcp dport 8080 jump svc`),
		v4("svc"):   nftRows(`ip saddr 198.51.100.0/24 accept`),
	}
	rows := foldChains([]baseChain{inputV4}, by)
	var accepts []fwRule
	for _, r := range rows {
		if r.Action == "accept" {
			accepts = append(accepts, r)
		}
	}
	if len(accepts) != 2 {
		t.Fatalf("accepts %+v, want svc folded under each path", accepts)
	}
	deep, flat := accepts[0], accepts[1]
	if deep.Depth != 2 || deep.Iif != "eth1" || deep.Dport != "8080" || deep.Proto != "tcp" || deep.Saddr != "198.51.100.0/24" {
		t.Errorf("the nested fold %+v, want iif eth1 + tcp/8080 + the source", deep)
	}
	if flat.Depth != 1 || flat.Iif != "" || flat.Dport != "443" {
		t.Errorf("the direct fold %+v, want tcp/443 without the interface", flat)
	}
}

// firewalld's iptables backend sends a trusted interface to an ACCEPT-target
// zone (`-i docker0 -g IN_trusted`, `-A IN_trusted -j ACCEPT`). Folded with
// its jump's interface, the accept is iif docker0 with no port — opaque, never
// an any-port accept that exposes every listener.
func TestFoldChainsFirewalldTrustedZoneIsOpaque(t *testing.T) {
	by := map[chainKey][]fwRule{
		v4("INPUT"):       iptRows(`-A INPUT -i lo -j ACCEPT`, `-A INPUT -j INPUT_ZONES`, `-A INPUT -m conntrack --ctstate INVALID -j DROP`, `-A INPUT -j REJECT --reject-with icmp-host-prohibited`),
		v4("INPUT_ZONES"): iptRows(`-A INPUT_ZONES -i docker0 -g IN_trusted`, `-A INPUT_ZONES -g IN_public`),
		v4("IN_trusted"):  iptRows(`-A IN_trusted -j ACCEPT`),
		v4("IN_public"):   iptRows(`-A IN_public -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW,UNTRACKED -j ACCEPT`),
	}
	rows := foldChains([]baseChain{inputV4}, by)
	var trusted, ssh *fwRule
	for i, r := range rows {
		switch r.Chain {
		case "IN_trusted":
			trusted = &rows[i]
		case "IN_public":
			ssh = &rows[i]
		}
		if classifyRule(r) == "any_port" {
			t.Errorf("any-port row: %+v", r)
		}
	}
	if trusted == nil || trusted.Iif != "docker0" || trusted.Depth != 2 || classifyRule(*trusted) != "opaque" {
		t.Errorf("the trusted zone's accept %+v, want iif docker0 at depth 2, opaque", trusted)
	}
	if ssh == nil || classifyRule(*ssh) != "port_rule" {
		t.Errorf("the public zone's ssh rule %+v, want a port_rule", ssh)
	}
}

// `ufw limit 22/tcp`: the `--set` row has no verdict (irrelevant), the
// `--update` jump leads to LOG and REJECT, and ufw-user-limit-accept's bare
// ACCEPT inherits tcp/22 from its jump — a port rule, nothing opaque.
func TestFoldChainsUfwLimitIsAPortRule(t *testing.T) {
	by := map[chainKey][]fwRule{
		v4("INPUT"): iptRows(`-A INPUT -j ufw-user-input`),
		v4("ufw-user-input"): iptRows(
			`-A ufw-user-input -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name DEFAULT --mask 255.255.255.255 --rsource`,
			`-A ufw-user-input -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 30 --hitcount 6 --name DEFAULT --mask 255.255.255.255 --rsource -j ufw-user-limit`,
			`-A ufw-user-input -p tcp -m tcp --dport 22 -j ufw-user-limit-accept`),
		v4("ufw-user-limit"):        iptRows(`-A ufw-user-limit -m limit --limit 3/min -j LOG --log-prefix "[UFW LIMIT BLOCK] "`, `-A ufw-user-limit -j REJECT --reject-with icmp-port-unreachable`),
		v4("ufw-user-limit-accept"): iptRows(`-A ufw-user-limit-accept -j ACCEPT`),
	}
	rows := foldChains([]baseChain{inputV4}, by)
	var ports []string
	for _, r := range rows {
		switch classifyRule(r) {
		case "opaque", "any_port":
			t.Errorf("row %+v classifies %q", r, classifyRule(r))
		case "port_rule":
			ports = append(ports, r.Proto+"/"+r.Dport+"@"+r.Chain)
		}
	}
	if !slices.Equal(ports, []string{"tcp/22@ufw-user-limit-accept"}) {
		t.Errorf("port rules %v, want the limit-accept's tcp/22", ports)
	}
}

func TestFoldChainsIgnoresANatChainOfTheSameName(t *testing.T) {
	by := map[chainKey][]fwRule{
		v4("INPUT"):          {{Action: "jump KUBE-NODEPORTS"}},
		v4("KUBE-NODEPORTS"): {},
		{Family: "v4", Table: "nat", Name: "KUBE-NODEPORTS"}: {{Proto: "tcp", Dport: "30443", Action: "accept"}},
	}
	rows := foldChains([]baseChain{inputV4}, by)
	if len(rows) != 1 || rows[0].Unmodelled {
		t.Fatalf("rows %+v, want the one followed jump and nothing from the nat table", rows)
	}
}

func TestClassifyRule(t *testing.T) {
	cases := []struct {
		r    fwRule
		want ruleClass
	}{
		{fwRule{Action: "drop"}, "deny"},
		{fwRule{Action: "reject", Unmodelled: true}, "deny"},
		{fwRule{Action: "accept", Proto: "tcp", Dport: "22"}, "port_rule"},
		{fwRule{Action: "accept", Proto: "udp", Dport: "{ 53, 123 }"}, "port_rule"},
		{fwRule{Action: "accept", Proto: "tcp", Dport: "22", Iif: "eth0"}, "port_rule"},
		{fwRule{Action: "accept"}, "any_port"},
		{fwRule{Action: "accept", Saddr: "192.0.2.0/24"}, "any_port"},
		{fwRule{Action: "accept", Ctstate: "new"}, "any_port"},
		{fwRule{Action: "accept", Iif: "lo"}, "loopback_only"},
		{fwRule{Action: "accept", Iif: "lo", Unmodelled: true}, "loopback_only"},
		{fwRule{Action: "accept", Ctstate: "established,related"}, "state_only"},
		{fwRule{Action: "accept", Ctstate: "established,related", Unmodelled: true}, "state_only"},
		{fwRule{Action: "accept", Ctstate: "new,established", Proto: "tcp", Dport: "22"}, "port_rule"},
		{fwRule{Action: "accept", Ctstate: "untracked", Proto: "tcp", Dport: "22"}, "port_rule"},
		{fwRule{Action: "accept", Proto: "icmp"}, "irrelevant"},
		{fwRule{Action: "accept", Proto: "ipv6-icmp", Unmodelled: true}, "irrelevant"},
		{fwRule{Action: "accept", Proto: "sctp", Dport: "22"}, "irrelevant"},
		{fwRule{Action: "accept", Proto: "50"}, "irrelevant"},
		{fwRule{Action: "accept", Proto: ".", Unmodelled: true}, "opaque"},
		{fwRule{Action: "accept", Proto: "all"}, "opaque"},
		{fwRule{Action: "accept", Proto: "0"}, "opaque"},
		{fwRule{Action: "accept", Proto: "comp"}, "opaque"},
		{fwRule{Action: "accept", Proto: "mystery"}, "opaque"},
		{fwRule{Action: "accept", Ctstate: "related,established,dnat"}, "opaque"},
		{fwRule{Action: "accept", Ctstate: "snat"}, "opaque"},
		{fwRule{Action: "accept", Ctstate: "invalid"}, "state_only"},
		{fwRule{Action: "none"}, "irrelevant"},
		{fwRule{Action: "none", Proto: "tcp", Dport: "22", Unmodelled: true}, "irrelevant"},
		{fwRule{Action: "masquerade"}, "opaque"},
		{fwRule{Action: "accept", Proto: "icmp", Unmodelled: true}, "irrelevant"},
		{fwRule{Action: "jump ufw-user-input"}, "irrelevant"},
		{fwRule{Action: "goto ufw-user-input"}, "irrelevant"},
		{fwRule{Action: "jump ufw-user-input", Unmodelled: true}, "opaque"}, // a jump the fold could not follow
		{fwRule{Action: "log"}, "irrelevant"},
		{fwRule{Action: "log", Unmodelled: true}, "irrelevant"},
		{fwRule{Action: "return", Unmodelled: true}, "irrelevant"},
		{fwRule{Action: "continue"}, "irrelevant"},
		{fwRule{Action: "queue"}, "opaque"},
		{fwRule{Action: "jump"}, "opaque"},
		{fwRule{Action: "accept", Unmodelled: true}, "opaque"},
		{fwRule{Action: "accept", Proto: "tcp", Dport: "22", Unmodelled: true}, "opaque"},
		{fwRule{Action: "accept", Proto: "tcp", Dport: "ssh"}, "opaque"},
		{fwRule{Action: "accept", Proto: "tcp"}, "opaque"},
		{fwRule{Action: "accept", Iif: "eth0"}, "opaque"},
		{fwRule{Action: "accept", Daddr: "203.0.113.1"}, "opaque"},
		{fwRule{Action: ""}, "opaque"},
	}
	for _, c := range cases {
		if got := classifyRule(c.r); got != c.want {
			t.Errorf("%+v: %q, want %q", c.r, got, c.want)
		}
	}
}

func TestParsePortSpec(t *testing.T) {
	type probe struct {
		port int
		want bool
	}
	cases := []struct {
		spec       string
		unmodelled bool
		probes     []probe
	}{
		{"22", false, []probe{{22, true}, {23, false}, {0, false}}},
		{"0", false, []probe{{0, true}}},
		{"65535", false, []probe{{65535, true}}},
		{"1000-2000", false, []probe{{1000, true}, {1500, true}, {2000, true}, {2001, false}, {999, false}}},
		{"1000:2000", false, []probe{{1500, true}, {2001, false}}},
		{"{ 22, 80 }", false, []probe{{22, true}, {80, true}, {443, false}}},
		{"{ 22, 8000-8080 }", false, []probe{{8080, true}, {8081, false}}},
		{"22,80,443", false, []probe{{443, true}, {444, false}}},
		{"ssh", true, nil},
		{"@ports", true, nil},
		{"", true, nil},
		{"65536", true, nil},
		{"2000-1000", true, nil},
		{"1000:", true, nil},
		{"+22", true, nil},
		{"{ 22, 80", true, nil},
		{"22,,80", true, nil},
	}
	for _, c := range cases {
		p := parsePortSpec(c.spec)
		if p.Unmodelled != c.unmodelled {
			t.Errorf("%q: unmodelled %v, want %v", c.spec, p.Unmodelled, c.unmodelled)
		}
		for _, pr := range c.probes {
			if got := p.matches(pr.port); got != pr.want {
				t.Errorf("%q matches %d = %v, want %v", c.spec, pr.port, got, pr.want)
			}
		}
		if p.Unmodelled && p.matches(22) {
			t.Errorf("%q: an unmodelled spec matched a port", c.spec)
		}
	}

	members := make([]string, 256)
	for i := range members {
		members[i] = strconv.Itoa(i + 1)
	}
	if p := parsePortSpec(strings.Join(members, ",")); p.Unmodelled || !p.matches(256) {
		t.Errorf("256 members: unmodelled %v, want enumerable", p.Unmodelled)
	}
	if p := parsePortSpec(strings.Join(append(members, "257"), ",")); !p.Unmodelled {
		t.Error("257 members must be unmodelled")
	}
	if p := parsePortSpec("{ " + strings.Join(append(members, "257"), ", ") + " }"); !p.Unmodelled {
		t.Error("a 257-member nft set must be unmodelled")
	}
}

// record and fwRuleFromRecord are inverses, and the record carries the
// fourteen fields of W-4 and W-59 and nothing else.
func TestFwRuleRecordRoundTrip(t *testing.T) {
	r := fwRule{Chain: "ufw-user-input", ViaChain: "INPUT", Table: "filter", Depth: 2, Family: "v4", Proto: "tcp", Dport: "80",
		Saddr: "192.0.2.0/24", Daddr: "198.51.100.1", Iif: "eth0", Ctstate: "new", Action: "accept", Unmodelled: true, Raw: "-A ufw-user-input …"}
	m := r.record()
	want := []string{"action", "chain", "ctstate", "daddr", "depth", "dport", "family", "iif", "proto", "raw", "saddr", "table", "unmodelled", "via_chain"}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, want) {
		t.Fatalf("record keys %v, want %v", keys, want)
	}
	if got := fwRuleFromRecord(m); got != r {
		t.Errorf("round trip %+v, want %+v", got, r)
	}
	// A snapshot read back from JSON carries depth as a float64.
	m["depth"] = float64(2)
	if got := fwRuleFromRecord(m); got != r {
		t.Errorf("round trip through a JSON number %+v, want %+v", got, r)
	}
	if got := fwRuleFromRecord(map[string]any{}); got != (fwRule{}) {
		t.Errorf("an empty record reads as %+v", got)
	}
}
