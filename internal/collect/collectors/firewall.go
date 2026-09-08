//go:build linux

package collectors

import (
	"bytes"
	"context"
	"strconv"
	"unicode/utf8"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The firewall collector reads the kernel firewall ruleset (the oracle) and
// the persisted backend configuration (the evidence). Task 1 captures and
// safely degrades; the ruleset NORMALISATION (restricts_inbound, the parsed
// rules, the runtime default policy) lands in Task 2, so those leaves are
// deliberately left absent/"none" here whenever a ruleset was read.
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

	// Task 1 reads the ruleset but does not yet normalise it: restricts_inbound
	// stays absent and rules an empty ok list until Task 2. normalization_
	// confidence is "none" (nothing normalised yet), or "partial" when a dump
	// was truncated — a partial ruleset can never yield a confident answer
	// (H-22), so even T2 must treat it as partial.
	b.Set("firewall.restricts_inbound", collect.Absent("normalization pending (Task 2)"))
	confidence := "none"
	if cr.truncated {
		confidence = "partial"
	}
	b.Set("firewall.normalization_confidence", collect.OK(confidence, cr.src))
	b.Set("firewall.rules", collect.OK([]any{}, cr.src))

	// enabled: runtime from the live ruleset (non-empty), persisted from the
	// on-disk configuration. default_policy has both sides too (H-18); its
	// runtime side is absent until Task 2 parses the base-chain policy.
	runtimeEnabled := collect.OKRead(cr.nonEmpty, cr.src, collect.ReadMeta{})
	b.SetSetting("firewall.enabled", facts.Setting{Runtime: envp(runtimeEnabled), Persisted: envp(cfg.persistedEnabled())})
	policyRuntime := collect.Absent("runtime default policy normalization pending (Task 2)")
	b.SetSetting("firewall.default_policy.input", facts.Setting{Runtime: envp(policyRuntime), Persisted: envp(cfg.persistedPolicy())})
	b.SetSetting("firewall.default_policy.forward", facts.Setting{Runtime: envp(policyRuntime), Persisted: envp(cfg.persistedPolicy())})
	return nil
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
