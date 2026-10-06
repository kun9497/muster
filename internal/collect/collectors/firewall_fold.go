package collectors

import (
	"strings"
	"unicode/utf8"
)

// This file holds the firewall collector's rule model: the row a parsed rule
// becomes (fwRule, the thirteen fields of firewall.rules), the two rule-line
// parsers, the fold of the user chains an input base chain reaches, and the
// classifier and port-spec reader the exposure verdict reads the rows with
// (W-38). It is untagged and standard-library only, so its tests run on every
// platform.

const (
	// fwRawCap is how much of one rule line a row's raw field carries (W-4).
	fwRawCap = 512
	// foldMaxDepth is the deepest jump the fold follows: the base chain's rows
	// are depth 0, ufw's accepts sit at depth 2.
	foldMaxDepth = 4
	// foldMaxRows bounds the folded (depth ≥ 1) rows of one base chain.
	foldMaxRows = 2000
	// portSpecMaxMembers bounds an enumerable port set (W-6).
	portSpecMaxMembers = 256
)

// fwRule is one firewall.rules row (W-4, spec P-2). Chain is the chain the
// rule was read from; ViaChain the input base chain whose jumps reached it
// (itself for a base-chain row) and Depth the number of jumps (0 for the base
// chain). Every selector the parser does not model leaves Unmodelled set; on
// a jump row, the fold redefines Unmodelled as "the jump was not followed".
type fwRule struct {
	Chain, ViaChain string
	Depth           int
	Family          string // v4 | v6 | inet
	Proto           string // tcp, udp, another literal, or ""
	Dport           string // a port, range or set as written
	Saddr, Daddr    string // the address or set text as written
	Iif             string
	Ctstate         string // lower-cased, comma-separated
	Action          string // accept, drop, reject, return, jump X, goto X, continue, queue, log, or ""
	Unmodelled      bool
	Raw             string
}

// record is the row as firewall.rules stores it: every field, always.
func (r fwRule) record() map[string]any {
	return map[string]any{
		"chain":      r.Chain,
		"via_chain":  r.ViaChain,
		"depth":      r.Depth,
		"family":     r.Family,
		"proto":      r.Proto,
		"dport":      r.Dport,
		"saddr":      r.Saddr,
		"daddr":      r.Daddr,
		"iif":        r.Iif,
		"ctstate":    r.Ctstate,
		"action":     r.Action,
		"unmodelled": r.Unmodelled,
		"raw":        r.Raw,
	}
}

// fwRuleFromRecord is record's inverse, for a row read back through the
// Builder or from a snapshot (where depth is a JSON number). A field of the
// wrong type reads as its zero value.
func fwRuleFromRecord(m map[string]any) fwRule {
	s := func(k string) string { v, _ := m[k].(string); return v }
	r := fwRule{
		Chain: s("chain"), ViaChain: s("via_chain"), Family: s("family"), Proto: s("proto"), Dport: s("dport"),
		Saddr: s("saddr"), Daddr: s("daddr"), Iif: s("iif"), Ctstate: s("ctstate"), Action: s("action"), Raw: s("raw"),
	}
	switch d := m["depth"].(type) {
	case int:
		r.Depth = d
	case int64:
		r.Depth = int(d)
	case float64:
		r.Depth = int(d)
	}
	r.Unmodelled, _ = m["unmodelled"].(bool)
	return r
}

// chainKey names a chain: a chain name is unique only within its family and
// table (W-33), so ufw's v4 and v6 chains, or a nat chain sharing a filter
// chain's name, never meet.
type chainKey struct{ Family, Table, Name string }

// baseChain is one parsed base chain (a chain that attaches to a netfilter
// hook and therefore carries a default policy): its name and table, its hook
// (input/forward/ingress/prerouting), the family it lives in, its chain type
// (filter/nat/route — only a filter chain can restrict, N1), its default
// policy (drop/reject/accept, or "" when the dump omitted the policy line) and
// whether it carries any rules.
type baseChain struct {
	name      string
	table     string
	hook      string
	family    string
	chainType string
	policy    string
	hasRules  bool
}

// capRaw cuts a rule line to fwRawCap bytes on a rune boundary.
func capRaw(s string) string {
	if len(s) <= fwRawCap {
		return s
	}
	cut := fwRawCap
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// protoName maps the numeric spellings of tcp and udp to their names, so a
// numeric protocol never reads as "another literal".
func protoName(p string) string {
	switch p {
	case "6":
		return "tcp"
	case "17":
		return "udp"
	}
	return p
}

// parseNftRule turns one nft rule line (split into fields) into a row. Each
// selector it models goes to its own field; `counter`, `comment` and a log
// statement's options are inert; any other token marks the row unmodelled.
// Parsing stops at the verdict (a reject's `with …` is its option). Family,
// via_chain and depth are the caller's.
func parseNftRule(chain string, f []string) fwRule {
	r := fwRule{Chain: chain, Raw: capRaw(strings.Join(f, " "))}
	for i := 0; i < len(f); i++ {
		switch t := f[i]; t {
		case "counter":
			// `counter packets N bytes N` (W-46).
			for i+2 < len(f) && (f[i+1] == "packets" || f[i+1] == "bytes") {
				i += 2
			}
		case "packets", "bytes":
			// a unit word (`burst 10 packets`): inert
		case "comment":
			_, i, _, _ = nftValue(f, i+1)
		case "iif", "iifname":
			v, next, neg, _ := nftValue(f, i+1)
			i = next
			if neg || v == "" {
				r.Unmodelled = true
			} else {
				r.Iif = unquote(v)
			}
		case "ct":
			if i+1 < len(f) && f[i+1] == "state" {
				v, next, neg, _ := nftValue(f, i+2)
				i = next
				if neg || v == "" {
					r.Unmodelled = true
				} else {
					r.Ctstate = ctStates(v)
				}
			} else {
				r.Unmodelled = true
			}
		case "ip", "ip6":
			if i+1 >= len(f) {
				r.Unmodelled = true
				continue
			}
			field := f[i+1]
			v, next, neg, set := nftValue(f, i+2)
			i = next
			switch {
			case neg || v == "":
				r.Unmodelled = true
			case field == "saddr":
				r.Saddr = v
			case field == "daddr":
				r.Daddr = v
			case field == "protocol" || field == "nexthdr":
				if set {
					r.Unmodelled = true // a protocol set (W-6)
				} else {
					r.Proto = protoName(v)
				}
			default:
				r.Unmodelled = true
			}
		case "meta":
			if i+1 >= len(f) {
				r.Unmodelled = true
				continue
			}
			field := f[i+1]
			v, next, neg, set := nftValue(f, i+2)
			i = next
			switch {
			case neg || v == "":
				r.Unmodelled = true
			case field == "l4proto":
				if set {
					r.Unmodelled = true
				} else {
					r.Proto = protoName(v)
				}
			case field == "iif" || field == "iifname":
				r.Iif = unquote(v)
			default:
				r.Unmodelled = true
			}
		case "tcp", "udp", "th", "sctp", "dccp", "udplite":
			if t != "th" {
				r.Proto = t
			}
			if i+1 >= len(f) {
				r.Unmodelled = true
				continue
			}
			field := f[i+1]
			v, next, neg, _ := nftValue(f, i+2)
			i = next
			switch {
			case field == "sport":
				// a source port narrows; inert, as --sport is
			case neg || v == "" || v == "vmap" || v == "map":
				r.Unmodelled = true
			case field == "dport":
				r.Dport = v
				if parsePortSpec(v).Unmodelled {
					r.Unmodelled = true
				}
			default:
				r.Unmodelled = true
			}
		case "icmp", "icmpv6", "igmp", "esp", "ah", "comp", "gre":
			// A header match: the protocol is known, the field is not modelled.
			if r.Proto == "" {
				r.Proto = t
			}
			r.Unmodelled = true
			if i+1 < len(f) {
				_, i, _, _ = nftValue(f, i+2)
			}
		case "log":
			if r.Action == "" {
				r.Action = "log"
			}
			for i+2 < len(f) && isNftLogOption(f[i+1]) {
				_, i, _, _ = nftValue(f, i+2)
			}
		case "accept", "drop", "reject", "return", "continue", "queue":
			r.Action = t
			return r
		case "jump", "goto":
			r.Action = t
			if i+1 < len(f) {
				r.Action = t + " " + f[i+1]
			}
			return r
		case "{":
			_, i, _, _ = nftValue(f, i)
			r.Unmodelled = true
		default:
			r.Unmodelled = true
		}
	}
	return r
}

func isNftLogOption(s string) bool {
	switch s {
	case "prefix", "level", "group", "snaplen", "queue-threshold", "flags":
		return true
	}
	return false
}

// nftValue reads the operand starting at f[i]: an optional `!=`, then one
// token, a `{ … }` set (gathered to its closing brace), a quoted string that
// spans fields, or a `vmap`/`map` keyword with its set (returned as the
// keyword). next is the index of the operand's last field.
func nftValue(f []string, i int) (v string, next int, neg, set bool) {
	if i < len(f) && f[i] == "!=" {
		neg = true
		i++
	}
	if i >= len(f) {
		return "", len(f) - 1, neg, false
	}
	switch tok := f[i]; {
	case tok == "vmap" || tok == "map":
		if i+1 < len(f) && strings.HasPrefix(f[i+1], "{") {
			_, end := gatherSet(f, i+1)
			return tok, end, neg, true
		}
		return tok, i, neg, false
	case strings.HasPrefix(tok, "{"):
		v, end := gatherSet(f, i)
		return v, end, neg, true
	case strings.HasPrefix(tok, `"`) && (len(tok) == 1 || !strings.HasSuffix(tok, `"`)):
		end := i + 1
		for end < len(f) && !strings.HasSuffix(f[end], `"`) {
			end++
		}
		if end >= len(f) {
			end = len(f) - 1
		}
		return strings.Join(f[i:end+1], " "), end, neg, false
	default:
		return tok, i, neg, false
	}
}

// gatherSet joins the fields of a `{ … }` set starting at f[i] through the
// field that balances its braces (or the last field).
func gatherSet(f []string, i int) (string, int) {
	depth := 0
	for j := i; j < len(f); j++ {
		depth += braceDelta(f[j])
		if depth <= 0 {
			return strings.Join(f[i:j+1], " "), j
		}
	}
	return strings.Join(f[i:], " "), len(f) - 1
}

// braceDelta is the number of '{' minus the number of '}' in s.
func braceDelta(s string) int {
	d := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			d++
		case '}':
			d--
		}
	}
	return d
}

// unquote strips one pair of surrounding double quotes.
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// ctStates normalises a conntrack state list — `a,b` or `{ a, b }` — to
// lower-cased, comma-separated names in the order written.
func ctStates(v string) string {
	v = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(v), "{"), "}")
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, strings.ToLower(s))
		}
	}
	return strings.Join(out, ",")
}

// parseIptablesRule turns one iptables-save `-A` line (split into fields)
// into a row. Matches it models go to their fields; `-m tcp|udp|multiport|
// comment|conntrack|state`, `--comment`, `--sport(s)` are inert; any other
// match marks the row unmodelled, as does a negated (`!`) match. Everything
// after `-j`/`-g` is the target's options (W-46).
func parseIptablesRule(chain string, f []string) fwRule {
	r := fwRule{Chain: chain, Raw: capRaw(strings.Join(f, " "))}
	i := 0
	if len(f) >= 2 && f[0] == "-A" {
		i = 2
	}
	for ; i < len(f); i++ {
		t := f[i]
		neg := false
		if t == "!" {
			neg = true
			if i++; i >= len(f) {
				r.Unmodelled = true
				break
			}
			t = f[i]
		}
		operand := func() string {
			if i+1 < len(f) {
				i++
				return f[i]
			}
			return ""
		}
		switch t {
		case "-p", "--protocol":
			v := operand()
			if neg || v == "" {
				r.Unmodelled = true
			} else {
				r.Proto = protoName(strings.ToLower(v))
			}
		case "-i", "--in-interface":
			v := operand()
			if neg || v == "" {
				r.Unmodelled = true
			} else {
				r.Iif = v
			}
		case "-s", "--source":
			v := operand()
			if neg || v == "" {
				r.Unmodelled = true
			} else {
				r.Saddr = v
			}
		case "-d", "--destination":
			v := operand()
			if neg || v == "" {
				r.Unmodelled = true
			} else {
				r.Daddr = v
			}
		case "-m", "--match":
			switch operand() {
			case "tcp", "udp", "multiport", "comment", "conntrack", "state":
			default:
				r.Unmodelled = true
			}
		case "--dport", "--destination-port", "--dports", "--destination-ports":
			v := operand()
			if neg || v == "" {
				r.Unmodelled = true
			} else {
				r.Dport = v
				if parsePortSpec(v).Unmodelled {
					r.Unmodelled = true
				}
			}
		case "--sport", "--source-port", "--sports", "--source-ports":
			operand()
		case "--ctstate", "--state":
			v := operand()
			if neg || v == "" {
				r.Unmodelled = true
			} else {
				r.Ctstate = ctStates(v)
			}
		case "--comment":
			if i+1 < len(f) {
				_, i, _, _ = nftValue(f, i+1)
			}
		case "-j", "--jump":
			r.Action = iptablesTarget(operand())
			return r
		case "-g", "--goto":
			if v := operand(); v != "" {
				r.Action = "goto " + v
			} else {
				r.Action = "goto"
			}
			return r
		default:
			r.Unmodelled = true
			if strings.HasPrefix(t, "-") {
				i = skipIptablesOperands(f, i)
			}
		}
	}
	return r
}

// iptablesTarget maps a -j target to the row's action: the built-in verdicts
// by name, any other target (a user chain, or an extension such as MARK that
// the fold will not find) as a jump (W-46).
func iptablesTarget(t string) string {
	switch t {
	case "":
		return ""
	case "ACCEPT":
		return "accept"
	case "DROP":
		return "drop"
	case "REJECT":
		return "reject"
	case "RETURN":
		return "return"
	case "LOG":
		return "log"
	case "QUEUE":
		return "queue"
	}
	return "jump " + t
}

// skipIptablesOperands skips the operands of the unknown option at f[i]: the
// fields up to the next option or `!`, a quoted operand counted as one.
func skipIptablesOperands(f []string, i int) int {
	for i+1 < len(f) && !strings.HasPrefix(f[i+1], "-") && f[i+1] != "!" {
		_, i, _, _ = nftValue(f, i+1)
	}
	return i
}

// jumpTarget returns the chain a `jump X` / `goto X` action names.
func jumpTarget(action string) (string, bool) {
	for _, p := range []string{"jump ", "goto "} {
		if t, ok := strings.CutPrefix(action, p); ok && t != "" {
			return t, true
		}
	}
	return "", false
}

// foldChains returns the rows of every filter base chain on the input hook,
// each followed by the rows of the chains its jumps and gotos reach, resolved
// within the base chain's family and table only (W-33): depth at most 4, at
// most 2000 folded rows per base chain, each chain visited once per base
// chain. A jump the fold could not follow — past the depth or the budget, or
// to a chain the dump does not hold (MARK, CT, …) — is marked unmodelled, so
// the classifier reads it opaque; a jump it did follow is not, whatever its
// match, since the rules it leads to are folded in unconditionally. Rule
// order is ignored (spec P-2). Folded rows never feed confidence (W-44).
func foldChains(bases []baseChain, byChain map[chainKey][]fwRule) []fwRule {
	out := []fwRule{}
	for _, bc := range bases {
		if bc.hook != "input" || bc.chainType != "filter" {
			continue
		}
		s := &foldState{bc: bc, by: byChain, visited: map[string]bool{bc.name: true}, budget: foldMaxRows}
		s.chain(bc.name, 0, &out)
	}
	return out
}

type foldState struct {
	bc      baseChain
	by      map[chainKey][]fwRule
	visited map[string]bool
	budget  int
}

// chain appends the rows of the named chain at depth and reports whether
// every one of them fitted in the budget. A jump in it that could not be
// followed is marked on its own row; that alone already makes the base
// chain's fold opaque, so it does not propagate to the jumps above it.
func (s *foldState) chain(name string, depth int, out *[]fwRule) bool {
	for _, r := range s.by[chainKey{s.bc.family, s.bc.table, name}] {
		if depth > 0 {
			if s.budget == 0 {
				return false
			}
			s.budget--
		}
		r.Chain, r.ViaChain, r.Depth, r.Family = name, s.bc.name, depth, s.bc.family
		at := len(*out)
		*out = append(*out, r)
		if target, ok := jumpTarget(r.Action); ok {
			(*out)[at].Unmodelled = !s.follow(target, depth, out)
		}
	}
	return true
}

// follow folds a jump's target one level deeper; true when the target was
// folded whole, now or earlier in this base chain's fold.
func (s *foldState) follow(target string, depth int, out *[]fwRule) bool {
	if s.visited[target] {
		return true
	}
	if _, ok := s.by[chainKey{s.bc.family, s.bc.table, target}]; !ok || depth+1 > foldMaxDepth {
		return false
	}
	s.visited[target] = true
	return s.chain(target, depth+1, out)
}

// ruleClass is what a row means to the exposure verdict (W-5, W-36).
type ruleClass string

// classifyRule reads one row, in W-36's order: deny; irrelevant (log, return,
// continue, a followed jump/goto, an accept of a literal protocol other than
// tcp/udp — whatever unmodelled says); loopback_only; state_only; port_rule
// or any_port only when nothing was left unmodelled; else opaque. A jump the
// fold could not follow carries unmodelled and is opaque.
func classifyRule(r fwRule) ruleClass {
	switch a := r.Action; {
	case a == "drop" || a == "reject":
		return "deny"
	case strings.HasPrefix(a, "jump ") || strings.HasPrefix(a, "goto "):
		if _, ok := jumpTarget(a); !ok || r.Unmodelled {
			return "opaque"
		}
		return "irrelevant"
	case a == "log" || a == "return" || a == "continue":
		return "irrelevant"
	case a != "accept":
		return "opaque"
	}
	l4 := r.Proto == "tcp" || r.Proto == "udp"
	switch {
	case r.Proto != "" && !l4:
		return "irrelevant"
	case r.Iif == "lo":
		return "loopback_only"
	case r.Ctstate != "" && !admitsNew(r.Ctstate):
		return "state_only"
	case r.Unmodelled:
		return "opaque"
	case l4 && r.Dport != "" && !parsePortSpec(r.Dport).Unmodelled:
		return "port_rule"
	case r.Proto == "" && r.Dport == "" && r.Iif == "" && r.Daddr == "":
		return "any_port"
	}
	return "opaque"
}

// admitsNew reports whether a conntrack state list lets a new connection in.
func admitsNew(ctstate string) bool {
	for _, s := range strings.Split(ctstate, ",") {
		if s == "new" || s == "untracked" {
			return true
		}
	}
	return false
}

// fwPortSpec is an enumerable destination-port operand (W-6). The Interfaces
// block calls it portSpec; that name is the services table's port row.
type fwPortSpec struct {
	Ranges     [][2]int
	Members    []int
	Unmodelled bool
}

// parsePortSpec reads a port, a range (`a-b` nft, `a:b` iptables), an nft set
// `{ a, b-c }` or an iptables multiport list `a,b,c` of at most 256 members.
// A service name, a named set, an open range or anything else is unmodelled.
func parsePortSpec(s string) fwPortSpec {
	none := fwPortSpec{Unmodelled: true}
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "{") {
		if !strings.HasSuffix(s, "}") {
			return none
		}
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	if s == "" || strings.Count(s, ",") >= portSpecMaxMembers {
		return none
	}
	var p fwPortSpec
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if n, ok := portNumber(part); ok {
			p.Members = append(p.Members, n)
			continue
		}
		sep := strings.IndexAny(part, "-:")
		if sep < 0 {
			return none
		}
		lo, ok1 := portNumber(part[:sep])
		hi, ok2 := portNumber(part[sep+1:])
		if !ok1 || !ok2 || lo > hi {
			return none
		}
		p.Ranges = append(p.Ranges, [2]int{lo, hi})
	}
	return p
}

// portNumber reads a decimal port 0..65535 (digits only).
func portNumber(s string) (int, bool) {
	if s == "" || len(s) > 5 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, n <= 65535
}

// matches reports whether port is in the spec; never for an unmodelled one.
func (p fwPortSpec) matches(port int) bool {
	if p.Unmodelled {
		return false
	}
	for _, m := range p.Members {
		if m == port {
			return true
		}
	}
	for _, r := range p.Ranges {
		if r[0] <= port && port <= r[1] {
			return true
		}
	}
	return false
}
