//go:build linux

package collectors

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The firewall collector reads the kernel firewall ruleset (the oracle) and
// the persisted backend configuration (the evidence). It captures and safely
// degrades the read (euid-classified, H-17), then normalises the captured
// ruleset into the inbound default policy, a bounded confidence and a
// restricts_inbound verdict (H-16), the runtime default_policy and the parsed
// inbound rules. The confidence boundary in runFirewall is deliberately
// under-claiming so the collector never emits a confident-wrong FAIL.
const (
	ufwConf       = "/etc/ufw/ufw.conf"
	ufwUserRules  = "/etc/ufw/user.rules"
	ufwDefault    = "/etc/default/ufw"
	firewalldConf = "/etc/firewalld/firewalld.conf"
	firewalldZone = "/etc/firewalld/zones/*.xml"
	nftablesConf  = "/etc/nftables.conf"
	iptablesRules = "/etc/iptables/rules.v4"
)

// rawDumpCap is how much of one ruleset dump firewall.raw_dumps carries. It
// is independent of the exec layer's 1 MiB output cap (a dump can hit either;
// H-22): a dump longer than this is stored truncated so the T2 normaliser
// never reads a partial ruleset as the whole answer. Larger than the 256-byte
// single-line rawCap because a ruleset is evidence that must be re-parsable.
const rawDumpCap = 64 * 1024

// The three ruleset-read commands. H-21: ONE nft invocation, `nft list
// ruleset` (NO `-a` — handles are noise in the dump and the T2 parser). The
// Command rendering (commandString) is the byte-identical key the guard and
// the raw_dumps `source` field both use.
var (
	nftListRulesetCmd = collect.Command{Path: "/usr/sbin/nft", Args: []string{"list", "ruleset"}}
	iptablesSaveCmd   = collect.Command{Path: "/usr/sbin/iptables-save"}
	ip6tablesSaveCmd  = collect.Command{Path: "/usr/sbin/ip6tables-save"}
)

var firewallCollector = collect.Collector{
	Name: "firewall",
	Declare: collect.Declaration{
		Reads: []string{
			ufwConf, ufwUserRules, ufwDefault,
			firewalldConf, firewalldZone,
			nftablesConf, iptablesRules,
		},
		Commands: []collect.Command{nftListRulesetCmd, iptablesSaveCmd, ip6tablesSaveCmd},
		// Needs: "none" — the collector classifies its OWN ruleset-read
		// failure by euid (H-17), so it never leans on the Needs annotation to
		// wrap a failure as denied.
		Needs: "none",
	},
	Run: runFirewall,
}

// capture is the outcome of trying to read the kernel ruleset.
type capture struct {
	dumps     []any         // one {source, content, truncated} record per command
	src       *facts.Source // the primary command, for citing the captured facts
	ok        bool          // at least one ruleset command succeeded
	tool      string        // "nft" | "iptables" — which backend answered
	nonEmpty  bool          // the ruleset carries at least one rule/table
	truncated bool          // any captured dump hit a cap (H-22)
	reason    string        // why nothing could be read (when !ok)
}

func runFirewall(ctx context.Context, a collect.Access, b *collect.Builder) error {
	cfg := readFirewallConfig(a)
	cr := captureRuleset(ctx, a)

	if !cr.ok {
		// H-17 / R220: the collector classifies its OWN failure by euid. A
		// failure as root (no CAP_NET_ADMIN, no netlink, tool absent — the
		// collect-contract container) is unsupported and keeps the run
		// complete; the same failure as a non-root process is honestly denied
		// (ERROR), which collect-nonroot expects. NEVER an error on this path.
		var deg facts.Envelope
		if euid() != 0 {
			deg = collect.Denied("reading the kernel firewall ruleset requires root: " + cr.reason)
		} else {
			deg = collect.Unsupported("no readable kernel firewall ruleset: " + cr.reason)
		}
		b.Set("firewall.backend", deg)
		b.Set("firewall.restricts_inbound", deg)
		b.Set("firewall.normalization_confidence", deg)
		b.Set("firewall.rules", deg)
		b.Set("firewall.raw_dumps", deg)
		// Both sides are always set (H-18). The runtime side carries the
		// classified degradation; the persisted side still reports whatever the
		// on-disk configuration says, since it is read independently of the
		// kernel ruleset.
		b.SetSetting("firewall.enabled", facts.Setting{Runtime: envp(deg), Persisted: envp(cfg.persistedEnabled())})
		b.SetSetting("firewall.default_policy.input", facts.Setting{Runtime: envp(deg), Persisted: envp(cfg.persistedPolicy())})
		b.SetSetting("firewall.default_policy.forward", facts.Setting{Runtime: envp(deg), Persisted: envp(cfg.persistedPolicy())})
		return nil
	}

	name, nameSrc := cfg.backend(cr)
	b.Set("firewall.backend", collect.OK(name, nameSrc))
	b.Set("firewall.raw_dumps", withTruncation(collect.OK(cr.dumps, cr.src), cr.truncated))

	// Normalise the captured ruleset (Task 2). Parse EVERY base chain that
	// hooks input or forward, across families, plus the inbound rules those
	// chains carry (evidence).
	bases, rules := normalizeRuleset(cr)
	b.Set("firewall.rules", collect.OK(rules, cr.src))
	var inputs, forwards []baseChain
	for _, bc := range bases {
		switch bc.hook {
		case "input":
			inputs = append(inputs, bc)
		case "forward":
			forwards = append(forwards, bc)
		}
	}

	// Ruling H-16 — the `full`-confidence boundary. The v1 normaliser claims
	// `full` ONLY in the two cases it can decide without modelling the rule
	// engine, and deliberately UNDER-claims (partial → restricts_inbound
	// absent → MANUAL) everywhere else so it never emits a confident-wrong
	// FAIL:
	//   - full + restricts_inbound ok:true — every input base chain across the
	//     ip/ip6/inet families has policy drop/reject (a family with no table
	//     is fine; IPv6 may simply be absent).
	//   - full + restricts_inbound ok:false — every input base chain has policy
	//     accept AND carries ZERO rules (no jump/goto/verdict lines), so the
	//     ruleset demonstrably does nothing inbound; also the readable-empty
	//     backend `none` case (nothing hooks input, netfilter accepts by
	//     default).
	//   - EVERYTHING ELSE → partial → restricts_inbound absent: an accept-policy
	//     chain that CARRIES rules (firewalld's filter_INPUT policy accept +
	//     terminal reject, or classic RHEL `:INPUT ACCEPT` + `-A INPUT -j
	//     REJECT`); mixed policies across chains or families; a missing policy
	//     line; or any truncated dump (H-22).
	// Rationale: the naive "policy accept ⇒ ok:false" rule FAILed firewalld and
	// classic RHEL iptables (accept base policy + a terminal reject genuinely
	// restrict inbound), and "exactly one input chain" made every dual-stack
	// (ip + ip6) host permanently MANUAL. This boundary fixes both.
	var confidence string
	var restricts facts.Envelope
	switch {
	case cr.truncated:
		// H-22: a partial ruleset can never yield a confident answer.
		confidence = "partial"
		restricts = collect.Absent("firewall confidence partial: a captured dump was truncated; see firewall.raw_dumps")
	case len(inputs) == 0 && name == "none":
		confidence = "full"
		restricts = collect.OK(false, cr.src)
	case len(inputs) == 0:
		confidence = "partial"
		restricts = collect.Absent("firewall confidence partial: ruleset not normalisable; no input base chain found; see firewall.raw_dumps")
	default:
		allDeny, allAcceptNoRules := true, true
		for _, c := range inputs {
			if !(c.policy == "drop" || c.policy == "reject") {
				allDeny = false
			}
			if !(c.policy == "accept" && !c.hasRules) {
				allAcceptNoRules = false
			}
		}
		switch {
		case allDeny:
			confidence = "full"
			restricts = collect.OK(true, cr.src)
		case allAcceptNoRules:
			confidence = "full"
			restricts = collect.OK(false, cr.src)
		default:
			confidence = "partial"
			restricts = collect.Absent("firewall confidence partial: ruleset not normalisable (an accept-policy chain carries rules, or policies differ across chains/families); see firewall.raw_dumps")
		}
	}
	b.Set("firewall.normalization_confidence", collect.OK(confidence, cr.src))
	b.Set("firewall.restricts_inbound", restricts)

	// enabled: runtime from the live ruleset (non-empty), persisted from the
	// on-disk configuration. default_policy has both sides too (H-18); its
	// runtime side is the parsed base-chain policy, its persisted side the
	// backend configuration.
	runtimeEnabled := collect.OKRead(cr.nonEmpty, cr.src, collect.ReadMeta{})
	b.SetSetting("firewall.enabled", facts.Setting{Runtime: envp(runtimeEnabled), Persisted: envp(cfg.persistedEnabled())})
	b.SetSetting("firewall.default_policy.input", facts.Setting{Runtime: envp(runtimePolicy(cr, inputs)), Persisted: envp(cfg.persistedPolicy())})
	b.SetSetting("firewall.default_policy.forward", facts.Setting{Runtime: envp(runtimePolicy(cr, forwards)), Persisted: envp(cfg.persistedPolicy())})
	return nil
}

// baseChain is one parsed base chain (a chain that attaches to a netfilter
// hook and therefore carries a default policy): its hook (input/forward), the
// family it lives in, its default policy (drop/reject/accept, or "" when the
// dump omitted the policy line) and whether it carries any rules.
type baseChain struct {
	hook     string
	family   string
	policy   string
	hasRules bool
}

// normalizeRuleset parses the captured dumps into the base chains and the
// inbound rules (evidence). nft answers with a single ruleset dump; the
// iptables path answers with a v4 and (optionally) a v6 dump, each parsed with
// its family. Rule order follows the dump order, which is deterministic.
func normalizeRuleset(cr capture) ([]baseChain, []any) {
	bases := []baseChain{}
	rules := []any{}
	for _, d := range cr.dumps {
		rec, ok := d.(map[string]any)
		if !ok {
			continue
		}
		content, _ := rec["content"].(string)
		if cr.tool == "nft" {
			b, r := parseNftRuleset(content)
			bases = append(bases, b...)
			rules = append(rules, r...)
			continue
		}
		// The dump's source is the command line (commandString): the v6 dump
		// comes from ip6tables-save, the only source carrying "ip6".
		family := "v4"
		if src, _ := rec["source"].(string); strings.Contains(src, "ip6") {
			family = "v6"
		}
		b, r := parseIptablesSave(family, content)
		bases = append(bases, b...)
		rules = append(rules, r...)
	}
	return bases, rules
}

// runtimePolicy is the runtime side of a default_policy setting: the common
// policy of every base chain on that hook. It is absent when the dump was
// truncated (untrustworthy), when no chain hooks there, or when the chains
// disagree or omit a policy — the honest answer, never a guess (H-18).
func runtimePolicy(cr capture, chains []baseChain) facts.Envelope {
	if cr.truncated {
		return collect.Absent("runtime default policy undetermined: a captured dump was truncated; see firewall.raw_dumps")
	}
	if len(chains) == 0 {
		return collect.Absent("no base chain hooks this point in the kernel ruleset")
	}
	p := chains[0].policy
	for _, c := range chains {
		if c.policy == "" || c.policy != p {
			return collect.Absent("runtime default policy undetermined: base chains disagree or omit a policy; see firewall.raw_dumps")
		}
	}
	return collect.OK(p, cr.src)
}

// parseNftRuleset walks `nft list ruleset` output with an explicit block
// stack, so a table's sets/maps/nested blocks never confuse the chain and
// table boundaries. It returns every input/forward base chain and the rules
// the input chains carry.
func parseNftRuleset(content string) ([]baseChain, []any) {
	bases := []baseChain{}
	rules := []any{}
	var stack []string // block kind per open brace: "table", "chain" or "other"
	curFamily, curChain := "", ""
	var cur baseChain
	isBase := false // the current chain hooks input/forward
	for _, raw := range splitLines([]byte(content)) {
		line := trimSpaceASCII(raw)
		if line == "" {
			continue
		}
		if line == "}" {
			if n := len(stack); n > 0 {
				top := stack[n-1]
				stack = stack[:n-1]
				switch top {
				case "chain":
					if isBase {
						bases = append(bases, cur)
					}
					isBase = false
				case "table":
					curFamily = ""
				}
			}
			continue
		}
		f := strings.Fields(line)
		if len(f) > 0 && line[len(line)-1] == '{' {
			switch {
			case len(stack) == 0 && f[0] == "table":
				if len(f) >= 2 {
					curFamily = f[1]
				}
				stack = append(stack, "table")
			case len(stack) == 1 && f[0] == "chain":
				curChain = ""
				if len(f) >= 2 {
					curChain = f[1]
				}
				cur = baseChain{family: curFamily}
				isBase = false
				stack = append(stack, "chain")
			default:
				stack = append(stack, "other")
			}
			continue
		}
		if len(stack) == 0 || stack[len(stack)-1] != "chain" {
			continue
		}
		if f[0] == "type" && strings.Contains(line, "hook") {
			if hook := nftHook(f); hook == "input" || hook == "forward" {
				isBase = true
				cur.hook = hook
				cur.policy = nftPolicy(f)
			}
			continue
		}
		if isBase {
			cur.hasRules = true
			if cur.hook == "input" {
				rules = append(rules, parseNftRule(curChain, f))
			}
		}
	}
	return bases, rules
}

// nftHook returns the token following "hook" in a base-chain type line.
func nftHook(f []string) string {
	for i := 0; i < len(f)-1; i++ {
		if f[i] == "hook" {
			return f[i+1]
		}
	}
	return ""
}

// nftPolicy returns the base-chain default policy (the token after "policy",
// stripped of its trailing ";"); "" when the line carries no policy keyword.
func nftPolicy(f []string) string {
	for i := 0; i < len(f)-1; i++ {
		if f[i] == "policy" {
			return strings.TrimRight(f[i+1], ";")
		}
	}
	return ""
}

// parseNftRule turns one nft rule line into an evidence record. It captures
// only what is cheap and unambiguous — the L4 protocol, the destination port
// (a string, since nft ports may be ranges or sets), the source address and
// the terminal verdict — and leaves the rest to firewall.raw_dumps.
func parseNftRule(chain string, f []string) map[string]any {
	rec := map[string]any{"chain": chain, "proto": "", "dport": "", "saddr": "", "action": ""}
	for i := 0; i < len(f); i++ {
		switch f[i] {
		case "tcp", "udp":
			rec["proto"] = f[i]
		case "dport":
			rec["dport"] = nftPortSpec(f, i+1)
		case "saddr":
			if i+1 < len(f) {
				rec["saddr"] = f[i+1]
			}
		case "accept", "drop", "reject", "return", "continue", "queue":
			rec["action"] = f[i]
		case "jump", "goto":
			if i+1 < len(f) {
				rec["action"] = f[i] + " " + f[i+1]
			} else {
				rec["action"] = f[i]
			}
		}
	}
	return rec
}

// nftPortSpec reads a destination-port operand starting at index i: a single
// token, or a "{ ... }" set gathered until the closing brace.
func nftPortSpec(f []string, i int) string {
	if i >= len(f) {
		return ""
	}
	if f[i] != "{" {
		return f[i]
	}
	var parts []string
	for ; i < len(f); i++ {
		parts = append(parts, f[i])
		if strings.Contains(f[i], "}") {
			break
		}
	}
	return strings.Join(parts, " ")
}

// parseIptablesSave parses one iptables-save / ip6tables-save dump. Only the
// `*filter` table's INPUT and FORWARD hooks are base chains with a default
// policy; their `:CHAIN POLICY` line gives the policy and their `-A CHAIN`
// lines both mark the chain as carrying rules and (for INPUT) become evidence.
func parseIptablesSave(family, content string) ([]baseChain, []any) {
	bases := []baseChain{}
	rules := []any{}
	table := ""
	for _, raw := range splitLines([]byte(content)) {
		line := trimSpaceASCII(raw)
		if line == "" || line[0] == '#' {
			continue
		}
		switch {
		case line[0] == '*':
			table = line[1:]
		case line == "COMMIT":
			table = ""
		case line[0] == ':' && table == "filter":
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			hook := iptablesHook(strings.TrimPrefix(f[0], ":"))
			if hook != "" {
				bases = append(bases, baseChain{hook: hook, family: family, policy: strings.ToLower(f[1])})
			}
		case strings.HasPrefix(line, "-A ") && table == "filter":
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			hook := iptablesHook(f[1])
			if hook == "" {
				continue
			}
			for j := range bases {
				if bases[j].hook == hook && bases[j].family == family {
					bases[j].hasRules = true
				}
			}
			if hook == "input" {
				rules = append(rules, parseIptablesRule(f[1], f))
			}
		}
	}
	return bases, rules
}

// iptablesHook maps a built-in chain name to the hook it attaches to; "" for a
// user-defined chain (which has no default policy).
func iptablesHook(chain string) string {
	switch chain {
	case "INPUT":
		return "input"
	case "FORWARD":
		return "forward"
	default:
		return ""
	}
}

// parseIptablesRule turns one `-A` line into an evidence record, reading the
// protocol, destination port, source and jump target.
func parseIptablesRule(chain string, f []string) map[string]any {
	rec := map[string]any{"chain": chain, "proto": "", "dport": "", "saddr": "", "action": ""}
	for i := 0; i < len(f)-1; i++ {
		switch f[i] {
		case "-p":
			rec["proto"] = f[i+1]
		case "--dport":
			rec["dport"] = f[i+1]
		case "-s":
			rec["saddr"] = f[i+1]
		case "-j":
			rec["action"] = strings.ToLower(f[i+1])
		}
	}
	return rec
}

// envp returns a pointer to a copy of e, for the Setting side fields.
func envp(e facts.Envelope) *facts.Envelope { return &e }

// cmdOK reports whether a command both started and exited cleanly.
func cmdOK(out collect.Output) bool {
	return out.Err == nil && !out.TimedOut && out.ExitCode == 0
}

// cmdReason is the human explanation a failed ruleset command carries: its
// first stderr line, or the start error / exit code when stderr is silent.
func cmdReason(what string, out collect.Output) string {
	if r := firstLine(out.Stderr); r != "" {
		return r
	}
	if out.Err != nil {
		return what + ": " + out.Err.Error()
	}
	return what + " exited " + strconv.Itoa(out.ExitCode)
}

// dumpRecord builds one raw_dumps record, capping the content at rawDumpCap on
// a rune boundary and marking it truncated when the content was cut here or
// the exec layer already truncated the capture (H-22).
func dumpRecord(source string, out collect.Output) map[string]any {
	content := out.Stdout
	truncated := out.Truncated
	if len(content) > rawDumpCap {
		cut := rawDumpCap
		for cut > 0 && !utf8.RuneStart(content[cut]) {
			cut--
		}
		content = content[:cut]
		truncated = true
	}
	return map[string]any{"source": source, "content": string(content), "truncated": truncated}
}

// captureRuleset runs `nft list ruleset`; on any failure it falls back to
// iptables-save (+ip6tables-save). It captures whatever succeeds and, when
// nothing does, carries the nft failure reason for the euid classification.
func captureRuleset(ctx context.Context, a collect.Access) capture {
	nftOut := a.Run(ctx, nftListRulesetCmd)
	if cmdOK(nftOut) {
		src := nftOut.Source(nftListRulesetCmd)
		rec := dumpRecord(src.Cmd, nftOut)
		return capture{
			dumps:     []any{rec},
			src:       src,
			ok:        true,
			tool:      "nft",
			nonEmpty:  len(bytes.TrimSpace(nftOut.Stdout)) > 0,
			truncated: rec["truncated"].(bool),
		}
	}
	reason := cmdReason("nft list ruleset", nftOut)

	ipOut := a.Run(ctx, iptablesSaveCmd)
	if !cmdOK(ipOut) {
		return capture{reason: reason}
	}
	src := ipOut.Source(iptablesSaveCmd)
	v4 := dumpRecord(src.Cmd, ipOut)
	c := capture{
		dumps:     []any{v4},
		src:       src,
		ok:        true,
		tool:      "iptables",
		nonEmpty:  len(bytes.TrimSpace(ipOut.Stdout)) > 0,
		truncated: v4["truncated"].(bool),
	}
	// ip6tables-save is best effort: an IPv6-less kernel or a missing binary
	// leaves the v4 capture intact rather than failing the whole read.
	ip6Out := a.Run(ctx, ip6tablesSaveCmd)
	if cmdOK(ip6Out) {
		v6 := dumpRecord(ip6Out.Source(ip6tablesSaveCmd).Cmd, ip6Out)
		c.dumps = append(c.dumps, v6)
		c.nonEmpty = c.nonEmpty || len(bytes.TrimSpace(ip6Out.Stdout)) > 0
		c.truncated = c.truncated || v6["truncated"].(bool)
	}
	return c
}

// fwConfig is the persisted backend evidence read from disk, independent of
// the kernel ruleset.
type fwConfig struct {
	hasFirewalld bool
	hasUfw       bool
	ufwEnabled   bool
	ufwReadErr   error
	ufwReadMeta  collect.ReadMeta
	hasNftConf   bool
	hasIptables  bool
	anyPresent   bool
}

func readFirewallConfig(a collect.Access) fwConfig {
	var c fwConfig
	c.hasFirewalld = statExists(a, firewalldConf) || globNonEmpty(a, firewalldZone)
	c.hasUfw = statExists(a, ufwConf) || statExists(a, ufwDefault)
	c.hasNftConf = statExists(a, nftablesConf)
	c.hasIptables = statExists(a, iptablesRules)
	if statExists(a, ufwConf) {
		data, meta, err := a.ReadFile(ufwConf, readLimit)
		if err != nil {
			c.ufwReadErr, c.ufwReadMeta = err, meta
		} else {
			c.ufwEnabled = ufwEnabledLine(data)
		}
	}
	c.anyPresent = c.hasFirewalld || c.hasUfw || c.hasNftConf || c.hasIptables
	return c
}

// backend names the configured backend, preferring the on-disk configuration
// and falling back to which tool answered the ruleset read.
func (c fwConfig) backend(cap capture) (string, *facts.Source) {
	switch {
	case c.hasFirewalld:
		return "firewalld", &facts.Source{Kind: "file", Path: firewalldConf}
	case c.hasUfw:
		return "ufw", &facts.Source{Kind: "file", Path: ufwConf}
	case c.hasNftConf:
		return "nftables", &facts.Source{Kind: "file", Path: nftablesConf}
	case cap.tool == "nft" && cap.nonEmpty:
		return "nftables", cap.src
	case c.hasIptables:
		return "iptables", &facts.Source{Kind: "file", Path: iptablesRules}
	case cap.tool == "iptables":
		return "iptables", cap.src
	default:
		// A readable but empty ruleset with no backend configuration.
		return "none", cap.src
	}
}

// persistedEnabled is the on-disk answer to "is a firewall configured on".
// H-18: absent when no backend configuration exists at all, the read error
// when the ufw config could not be read, otherwise a definite bool.
//
// Limit (T2 non-blocking concern): ufw is precise — it reads ENABLED=yes. The
// other backends still answer true on mere config presence, which overclaims a
// firewalld/nftables/iptables service that is installed but not enabled;
// deciding that cheaply would need a systemctl is-enabled probe the collector
// does not declare, so v1 leaves it at presence and the runtime side (the live
// ruleset) remains the authoritative half of the setting.
func (c fwConfig) persistedEnabled() facts.Envelope {
	if c.ufwReadErr != nil {
		return collect.FromReadError(c.ufwReadErr, c.ufwReadMeta)
	}
	if !c.anyPresent {
		return collect.Absent("no firewall backend configuration present")
	}
	val := c.hasFirewalld || (c.hasUfw && c.ufwEnabled) || c.hasNftConf || c.hasIptables
	return collect.OK(val, &facts.Source{Kind: "file", Path: c.evidencePath()})
}

// persistedPolicy is the on-disk default policy. H-18: absent when no
// configuration exists, unsupported when it does but v1 does not model the
// persisted policy value (Task 2 adds the per-backend parsing).
func (c fwConfig) persistedPolicy() facts.Envelope {
	if !c.anyPresent {
		return collect.Absent("no firewall backend configuration present")
	}
	return collect.Unsupported("v1 does not model the persisted default policy")
}

func (c fwConfig) evidencePath() string {
	switch {
	case c.hasFirewalld:
		return firewalldConf
	case c.hasUfw:
		return ufwConf
	case c.hasNftConf:
		return nftablesConf
	default:
		return iptablesRules
	}
}

// statExists reports whether a path is present. A stat that failed for any
// reason other than "there" is treated as not-present for detection: the
// authoritative privilege story is the kernel ruleset read, not a config
// stat, so a denied config stat must not masquerade as a firewall backend.
func statExists(a collect.Access, p string) bool {
	_, err := a.Stat(p)
	return err == nil
}

func globNonEmpty(a collect.Access, pattern string) bool {
	m, err := a.Glob(pattern)
	return err == nil && len(m) > 0
}

// ufwEnabledLine reports whether ufw.conf carries ENABLED=yes (ufw compares
// it case-insensitively).
func ufwEnabledLine(data []byte) bool {
	for _, line := range splitLines(data) {
		if key, val, ok := cutKeyValue(line); ok && key == "ENABLED" {
			return equalFoldASCII(val, "yes")
		}
	}
	return false
}

// cutKeyValue splits a KEY=VALUE shell-style assignment, ignoring comments and
// surrounding space; ok is false for a line that is not an assignment.
func cutKeyValue(line string) (key, val string, ok bool) {
	line = trimSpaceASCII(line)
	if line == "" || line[0] == '#' {
		return "", "", false
	}
	for i := 0; i < len(line); i++ {
		if line[i] == '=' {
			return trimSpaceASCII(line[:i]), trimSpaceASCII(line[i+1:]), true
		}
	}
	return "", "", false
}

func trimSpaceASCII(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
