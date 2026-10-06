package collectors

import (
	"cmp"
	"fmt"
	"net"
	"slices"
	"strings"
)

// This file holds the exposure verdict (spec P-3): for every listener that is
// not on loopback, whether a packet from off the host can reach it through
// the firewall's folded, classified rule table. It is untagged and reads only
// values, so its tests run on every platform; the processes collector feeds it
// what it read through Builder.Get.

// exposureInputs is what the verdict reads besides the listeners.
type exposureInputs struct {
	Confidence string // firewall.normalization_confidence: full or partial
	Restricts  *bool  // firewall.restricts_inbound; nil when absent
	Rules      []fwRule
	Backend    string
	BindV6Only int  // net.ipv6.bindv6only: 0 lets a socket on :: take v4 traffic too
	HasV6      bool // a v6 socket table exists, so the host speaks v6 (W-40)
	// BaseFamilies are the families (v4, v6, inet) that hold an input filter
	// base chain. A base chain with no rule leaves no row in Rules, so the
	// rows alone cannot tell "no chain in this family" from "a drop chain
	// with nothing in it"; the processes collector reads them back from the
	// raw dumps. A family a row names has a base chain whatever this says.
	BaseFamilies map[string]bool
}

// exposureRow is one exposure.listeners row; the exposed subset is the rows
// with Exposed set.
type exposureRow struct {
	Service, Proto, Family, Addr string
	Port                         int
	LinkLocal                    bool
	OwnerStatus                  string
	Owners                       []owner
	Exposed                      bool
	// Via is how the verdict was reached: no_chain_in_family, open_policy,
	// any_port_rule or rule when exposed; filtered when no path in was
	// found; undecided when the verdict could not be read.
	Via                            string
	RuleChain, RuleSource, RuleRaw string
}

// The vocabulary of exposureRow.Via.
const (
	viaNoChain   = "no_chain_in_family"
	viaOpen      = "open_policy"
	viaAnyPort   = "any_port_rule"
	viaRule      = "rule"
	viaFiltered  = "filtered"
	viaUndecided = "undecided"
)

// serviceOf is the string an allow list names: "tcp/22", never "tcp6/22"
// (W-10).
func serviceOf(proto string, port int) string {
	return fmt.Sprintf("%s/%d", strings.ToLower(strings.TrimSuffix(proto, "6")), port)
}

// isLoopback is an address in 127.0.0.0/8 or ::1: nothing from off the host
// reaches it.
func isLoopback(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && ip.IsLoopback()
}

// candidateFamilies are the families whose packets reach a socket bound to
// addr: 0.0.0.0 takes v4; :: takes v6 and, when bindv6only is 0, v4 too; a
// specific address takes its own family (a v4-mapped address prints dotted
// and is v4).
func candidateFamilies(addr string, bindV6Only int) []string {
	switch addr {
	case "0.0.0.0":
		return []string{"v4"}
	case "::":
		if bindV6Only == 0 {
			return []string{"v6", "v4"}
		}
		return []string{"v6"}
	}
	if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
		return []string{"v6"}
	}
	return []string{"v4"}
}

// inFamily reports a row of family fam or of an inet table, which carries
// both.
func inFamily(r fwRule, fam string) bool { return r.Family == fam || r.Family == "inet" }

// opaqueReason is the MANUAL cause an opaque row gives (W-3).
func opaqueReason(r fwRule) string {
	kind := "opaque rule"
	if r.Action == "accept" {
		kind = "opaque accept rule"
	}
	return fmt.Sprintf("%s in %s (%s, %s): %s", kind, r.Chain, r.Table, r.Family, r.Raw)
}

// decideExposure decides, per non-loopback listener, whether a packet from
// off the host can reach it (spec P-3, W-5, W-6). A listener is decided in a
// family only when the confidence is full and no row of that family (or of
// an inet table) is opaque; it is exposed when any of its candidate families
// says so. One undecided listener makes the verdict unreadable: manualReason
// is then the first cause (the confidence, or the first opaque row of the
// family that stopped it). rows are every non-loopback listener sorted by
// proto, port and addr; exposed the exposed subset; opaque every opaque row
// in rule order.
func decideExposure(ls []listener, in exposureInputs) (rows []exposureRow, exposed []exposureRow, opaque []fwRule, manualReason string) {
	rows, exposed, opaque = []exposureRow{}, []exposureRow{}, []fwRule{}
	chain := map[string]bool{}
	for f, ok := range in.BaseFamilies {
		chain[f] = chain[f] || ok
	}
	var anyPort, portRules []fwRule
	for _, r := range in.Rules {
		chain[r.Family] = true
		switch classifyRule(r) {
		case "opaque":
			opaque = append(opaque, r)
		case "any_port":
			anyPort = append(anyPort, r)
		case "port_rule":
			portRules = append(portRules, r)
		}
	}
	hasChain := func(fam string) bool { return chain[fam] || chain["inet"] }
	enabled := map[string]bool{"v4": true, "v6": in.HasV6}
	other := map[string]string{"v4": "v6", "v6": "v4"}
	firstOpaque := func(fam string) *fwRule {
		for i := range opaque {
			if inFamily(opaque[i], fam) {
				return &opaque[i]
			}
		}
		return nil
	}

	// decide is one family's verdict on a listener already known decidable
	// in it.
	decide := func(row *exposureRow, fam string) bool {
		switch {
		case enabled[fam] && !hasChain(fam) && hasChain(other[fam]):
			row.Via = viaNoChain
			return true
		case in.Restricts != nil && !*in.Restricts:
			row.Via = viaOpen
			return true
		}
		for _, r := range anyPort {
			if inFamily(r, fam) {
				row.Via, row.RuleChain, row.RuleSource, row.RuleRaw = viaAnyPort, r.Chain, r.Saddr, r.Raw
				return true
			}
		}
		for _, r := range portRules {
			if inFamily(r, fam) && r.Proto == row.Proto && parsePortSpec(r.Dport).matches(row.Port) {
				row.Via, row.RuleChain, row.RuleSource, row.RuleRaw = viaRule, r.Chain, r.Saddr, r.Raw
				return true
			}
		}
		return false
	}

	for _, l := range ls {
		if l.Loopback || isLoopback(l.Addr) {
			continue
		}
		proto, family := foldProto(strings.ToLower(l.Proto))
		if l.Family != "" {
			family = l.Family
		}
		row := exposureRow{Service: serviceOf(proto, l.Port), Proto: proto, Family: family, Addr: l.Addr, Port: l.Port,
			LinkLocal: l.LinkLocal || isLinkLocal(l.Addr), OwnerStatus: l.OwnerStatus, Owners: l.Owners}
		if row.Owners == nil {
			row.Owners = []owner{}
		}
		undecided := ""
		if in.Confidence != "full" {
			undecided = "normalization confidence is " + in.Confidence
		} else {
			stopped := ""
			for _, fam := range candidateFamilies(l.Addr, in.BindV6Only) {
				if o := firstOpaque(fam); o != nil {
					if stopped == "" {
						stopped = opaqueReason(*o)
					}
					continue
				}
				if decide(&row, fam) {
					row.Exposed = true
					break
				}
			}
			if !row.Exposed {
				undecided = stopped
			}
		}
		switch {
		case row.Exposed:
		case undecided != "":
			row.Via = viaUndecided
			if manualReason == "" {
				manualReason = undecided
			}
		default:
			row.Via = viaFiltered
		}
		rows = append(rows, row)
	}
	slices.SortStableFunc(rows, func(x, y exposureRow) int {
		return cmp.Or(cmp.Compare(x.Proto, y.Proto), cmp.Compare(x.Port, y.Port), cmp.Compare(x.Addr, y.Addr), cmp.Compare(x.Family, y.Family))
	})
	for _, r := range rows {
		if r.Exposed {
			exposed = append(exposed, r)
		}
	}
	return rows, exposed, opaque, manualReason
}

// record is the exposure.listeners row; owners are capped at ownersCap as in
// processes.listeners.
func (r exposureRow) record(ownersCap int) map[string]any {
	owners := make([]any, 0, min(len(r.Owners), ownersCap))
	for i, o := range r.Owners {
		if i == ownersCap {
			break
		}
		owners = append(owners, o.record())
	}
	return map[string]any{
		"service": r.Service, "proto": r.Proto, "family": r.Family, "addr": r.Addr, "port": r.Port,
		"link_local": r.LinkLocal, "owner_status": r.OwnerStatus, "owners": owners, "owners_count": len(r.Owners),
		"exposed": r.Exposed, "via": r.Via, "rule_chain": r.RuleChain, "rule_source": r.RuleSource, "rule_raw": r.RuleRaw,
	}
}

// exposedRecord is the exposure.exposed row: the owner shown is the lowest
// pid; a socket the kernel holds shows pid -1 and empty name and package.
func (r exposureRow) exposedRecord() map[string]any {
	pid, name, pkg := -1, "", ""
	for _, o := range r.Owners {
		if pid == -1 || o.Pid < pid {
			pid, name, pkg = o.Pid, o.Name, o.Package
		}
	}
	return map[string]any{
		"service": r.Service, "proto": r.Proto, "family": r.Family, "addr": r.Addr, "port": r.Port,
		"pid": pid, "name": name, "package": pkg, "via": r.Via, "rule_chain": r.RuleChain, "rule_source": r.RuleSource,
	}
}

// opaqueRecord is the exposure.opaque_rules row.
func opaqueRecord(r fwRule) map[string]any {
	return map[string]any{"chain": r.Chain, "via_chain": r.ViaChain, "table": r.Table, "family": r.Family, "action": r.Action, "raw": r.Raw}
}
