//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The snmp collector reads net-snmp's configuration — the main file, the
// Debian site override, the drop-in directory, and the root-only persistent
// state file each of the two families writes — and publishes what versions
// are enabled, what communities exist, what v3 users exist and what the VACM
// rules say.
//
// REDACTION (Ruling J-7) is the point of this collector, and it is FIELD
// DISCIPLINE, not machinery: the snapshot writer's Redaction header is static
// today, so nothing downstream will strip a secret this file chooses to
// publish. A community string and a v3 auth/priv passphrase therefore never
// reach an envelope value, a reason, a Source, or a record field — not even
// hashed, because a hash of a short, low-entropy string is trivially
// reversible by anyone holding the same well-known word list this file
// embeds. A community is described by an opaque ordinal (c1, c2, … in file
// order), its kind, whether it is one of the well-known defaults, its rune
// length and whether its source is restricted; that is everything U-59/U-60/
// U-61 need and nothing an attacker can use. The keys carry
// `sensitivity: secret` — the registry's first use of that level — so a later
// stage's redaction machinery (2M) can find them, but the guarantee today is
// this file.
const (
	snmpdConfPath      = "/etc/snmp/snmpd.conf"
	snmpdLocalConfPath = "/etc/snmp/snmpd.local.conf"
	snmpdConfDDir      = "/etc/snmp/snmpd.conf.d"
	snmpdConfDGlob     = snmpdConfDDir + "/*.conf"
	snmpStatePath      = "/var/lib/snmp/snmpd.conf"
	snmpNetStatePath   = "/var/lib/net-snmp/snmpd.conf"
	snmpIncludeSuffix  = "/*.conf"
)

// snmpCandidates is every file the collector reads on its own initiative, in
// the order it reads them. Includes found inside them are expanded in place
// (net-snmp reads includeFile/includeDir at the point the directive appears),
// so this list is a starting set, not the whole set.
func snmpCandidates() []string {
	return []string{snmpdConfPath, snmpdLocalConfPath}
}

// snmpStateFiles are the persistent files net-snmp itself writes — the
// createUser lines it moves out of snmpd.conf end up here. Both families'
// locations are read; only one exists on a given host.
func snmpStateFiles() []string {
	return []string{snmpStatePath, snmpNetStatePath}
}

var snmpCollector = collect.Collector{
	Name: "snmp",
	Declare: collect.Declaration{
		Reads: []string{
			snmpdConfPath,
			snmpdLocalConfPath,
			snmpdConfDGlob,
			snmpStatePath,
			snmpNetStatePath,
		},
		// Needs: "root" is DOCUMENTATION — the persistent state file is
		// 0600 root, and Ubuntu ships a 0600 snmpd.conf, so a non-root run
		// genuinely cannot see the whole configuration. Nothing branches on
		// it: the classification is FromReadError, so a non-root run says
		// denied because the read said EACCES, not because a flag said root
		// (Ruling J-6/J-27).
		Needs: "root",
	},
	Run: runSnmp,
}

// snmpDefaultCommunities is the embedded well-known list is_default is
// computed against. It is embedded rather than a control parameter because
// spec §5.6 forbids a parameter that would expose a secret: a site that
// listed its own community strings in a parameter to "check them" would be
// publishing them into every result file.
var snmpDefaultCommunities = map[string]bool{
	"public":    true,
	"private":   true,
	"community": true,
	"snmp":      true,
	"snmpd":     true,
	"manager":   true,
	"admin":     true,
	"default":   true,
	"cisco":     true,
	"secret":    true,
	"read":      true,
	"write":     true,
}

// snmpUser accumulates one v3 user across the two files that can describe
// it: the persistent state file's createUser carries the key material (and
// therefore what security level the user's credentials actually support),
// while snmpd.conf's rouser/rwuser carries the minimum level access requires.
// Keeping them apart makes the merge independent of which file was read
// first.
type snmpUser struct {
	name        string
	authProto   string
	privProto   string
	keyLevel    string // implied by the createUser key material
	accessLevel string // the rouser/rwuser minimum level
}

// snmpGroup is one `group NAME MODEL SECNAME` line: it is what turns a
// com2sec security name into an enabled protocol version.
type snmpGroup struct {
	name    string
	model   string
	secName string
}

// snmpCom2secRef remembers where a com2sec-derived community landed in the
// communities list so its kind can be resolved once every group and access
// line has been seen, whatever order the files were read in.
type snmpCom2secRef struct {
	secName string
	index   int
}

// snmpParse is the whole parse state. Everything ordered is a slice; the
// maps are lookup-only, so no map iteration ever decides an output order.
type snmpParse struct {
	a    collect.Access
	seen map[string]bool

	files       []string
	communities []any
	rules       []any
	agents      []any

	users     map[string]*snmpUser
	userNames []string

	groups       []snmpGroup
	accessWrites map[string][]string
	com2secNames map[string]bool
	com2secRefs  []snmpCom2secRef

	communityDirective bool

	// readFailure is the first read that failed for a reason other than
	// "not there"; undeclared lists every include the declaration does not
	// cover. Either one means the configuration was not seen in full.
	readFailure *facts.Envelope
	undeclared  []string
}

// runSnmp reads the configuration stack and publishes the seven snmp keys.
//
// C3: a file the collector reads that EXISTS but cannot be read is the answer
// for every value it could set — versions_enabled, communities and v3_users
// all carry that read's status rather than a confident answer built from the
// files that happened to be readable. A file that is simply absent
// contributes nothing and the parse continues; a host with no snmpd
// configuration at all cannot be said to have v1 disabled, so the three
// judged lists are absent (→ MANUAL) while the evidence leaves stay ok and
// the run stays complete.
func runSnmp(_ context.Context, a collect.Access, b *collect.Builder) error {
	p := &snmpParse{
		a:            a,
		seen:         map[string]bool{},
		users:        map[string]*snmpUser{},
		accessWrites: map[string][]string{},
		com2secNames: map[string]bool{},
		communities:  []any{},
		rules:        []any{},
		agents:       []any{},
	}
	p.scan()
	p.resolveCom2secKinds()

	src := &facts.Source{Kind: "file", Path: snmpdConfPath}
	if judged := p.judged(); judged != nil {
		b.Set("snmp.versions_enabled", *judged)
		b.Set("snmp.communities", *judged)
		b.Set("snmp.v3_users", *judged)
	} else {
		b.Set("snmp.versions_enabled", collect.OK(p.versions(), src))
		b.Set("snmp.communities", collect.OK(p.communities, src))
		b.Set("snmp.v3_users", collect.OK(p.v3Users(), src))
	}
	b.Set("snmp.access_rules", collect.OK(p.rules, src))
	b.Set("snmp.agent_addresses", collect.OK(p.agents, src))
	b.Set("snmp.config_files", collect.OK(p.sortedFiles(), src))
	b.Set("snmp.parse_complete", collect.OK(p.complete(), src))
	return nil
}

// scan reads the candidate files in a fixed order: the main file and its
// site override (each expanding its own includes in place), then the declared
// drop-in directory, then the persistent state files.
func (p *snmpParse) scan() {
	for _, f := range snmpCandidates() {
		p.readFile(f, 0)
	}
	matches, err := p.a.Glob(snmpdConfDGlob)
	if err != nil {
		p.fail(collect.ErrorEnv("glob " + snmpdConfDGlob + ": " + err.Error()))
	} else {
		sort.Strings(matches)
		for _, m := range matches {
			p.readFile(m, 0)
		}
	}
	for _, f := range snmpStateFiles() {
		p.readFile(f, 0)
	}
}

// readFile reads one configuration file and parses it. A path is parsed at
// most once however it was reached, so a fragment named by an includeDir and
// then found again by the declared drop-in glob contributes one set of
// records, not two.
func (p *snmpParse) readFile(file string, depth int) {
	file = path.Clean(file)
	if p.seen[file] {
		return
	}
	p.seen[file] = true
	if depth > maxIncludeDepth {
		p.fail(collect.ErrorEnv("include nesting deeper than " + strconv.Itoa(maxIncludeDepth) + " levels at " + file))
		return
	}
	data, meta, err := p.a.ReadFile(file, readLimit)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return
		}
		e := collect.FromReadError(err, meta)
		e.Reason = file + ": " + e.Reason
		p.fail(e)
		return
	}
	p.files = append(p.files, file)
	p.parse(data, depth)
}

// fail records the first read that could not answer. The first is kept
// rather than the worst so the reason names the file the collector reached
// first in its own fixed order — the same input always yields the same reason.
func (p *snmpParse) fail(e facts.Envelope) {
	if p.readFailure == nil {
		p.readFailure = &e
	}
}

// parse walks one file's directives in order. net-snmp matches its
// configuration tokens case-insensitively (agentAddress and agentaddress are
// one directive), so the keyword is folded; every value keeps its own case.
func (p *snmpParse) parse(data []byte, depth int) {
	for _, raw := range splitLines(data) {
		line := strings.TrimSpace(snmpStripComment(raw))
		if line == "" {
			continue
		}
		toks := snmpTokens(line)
		if len(toks) == 0 {
			continue
		}
		p.directive(strings.ToLower(toks[0]), toks[1:], depth)
	}
}

func (p *snmpParse) directive(keyword string, args []string, depth int) {
	switch keyword {
	case "rocommunity", "rocommunity6":
		p.community("ro", args)
	case "rwcommunity", "rwcommunity6":
		p.community("rw", args)
	case "com2sec", "com2sec6":
		p.com2sec(args)
	case "group":
		p.group(args)
	case "view":
		p.view(args)
	case "access":
		p.access(args)
	case "createuser":
		p.createUser(args)
	case "rouser", "rwuser":
		p.roleUser(args)
	case "agentaddress":
		p.agentAddress(args)
	case "includefile":
		p.includeFile(args, depth)
	case "includedir":
		p.includeDir(args, depth)
	}
}

// community records one rocommunity/rwcommunity directive:
// `rocommunity COMMUNITY [SOURCE [OID | -V VIEW]]`. The community is the
// second token and never leaves this function; the third token is the source
// unless it is an option flag or an OID subtree (snmpIsSourceToken draws that
// boundary).
func (p *snmpParse) community(kind string, args []string) {
	if len(args) == 0 {
		return
	}
	p.communityDirective = true
	source := ""
	if len(args) > 1 && snmpIsSourceToken(args[1]) {
		source = args[1]
	}
	p.addCommunity(kind, args[0], source)
}

// com2sec records `com2sec [-Cn CONTEXT] NAME SOURCE COMMUNITY`. The three
// positional fields are easy to transpose and the consequence of doing so is
// a leak, so they are read by position from the end of the option prefix: the
// COMMUNITY is LAST and the SOURCE is the middle field. The community's kind
// is not known here — it depends on the group and access lines this security
// name reaches — and is resolved after the whole stack is parsed.
func (p *snmpParse) com2sec(args []string) {
	if len(args) >= 2 && strings.EqualFold(args[0], "-Cn") {
		args = args[2:]
	}
	if len(args) < 3 {
		return
	}
	name, source, community := args[0], args[1], args[2]
	p.com2secNames[name] = true
	p.rules = append(p.rules, snmpRule("com2sec", name, "", "", source, "", ""))
	p.com2secRefs = append(p.com2secRefs, snmpCom2secRef{secName: name, index: len(p.communities)})
	p.addCommunity("ro", community, source)
}

// addCommunity appends the redacted description of one community string. The
// string is measured and classified here and discarded on return; ref is its
// one-based position in file order, which is opaque outside the snapshot and
// stable for the same input.
func (p *snmpParse) addCommunity(kind, community, source string) {
	p.communities = append(p.communities, map[string]any{
		"ref":               "c" + strconv.Itoa(len(p.communities)+1),
		"kind":              kind,
		"is_default":        snmpDefaultCommunities[strings.ToLower(community)],
		"length":            utf8.RuneCountInString(community),
		"source_restricted": snmpSourceRestricted(source),
	})
}

// group records `group GROUPNAME MODEL SECNAME`. The record has no field for
// a security name, so it travels in `source` — the thing the group draws its
// members from; the registry description says so.
func (p *snmpParse) group(args []string) {
	if len(args) < 3 {
		return
	}
	p.groups = append(p.groups, snmpGroup{name: args[0], model: args[1], secName: args[2]})
	p.rules = append(p.rules, snmpRule("group", args[0], args[1], "", args[2], "", ""))
}

// view records `view NAME included|excluded SUBTREE [MASK]`: the inclusion
// travels in sec_level and the OID subtree in source.
func (p *snmpParse) view(args []string) {
	if len(args) < 3 {
		return
	}
	p.rules = append(p.rules, snmpRule("view", args[0], "", args[1], args[2], "", ""))
}

// access records `access GROUP CONTEXT MODEL LEVEL PREFIX READ WRITE NOTIFY`
// — the VACM rule that decides what a security name may actually do. The
// write view is what makes a com2sec community read-write.
func (p *snmpParse) access(args []string) {
	if len(args) < 7 {
		return
	}
	group, context, model, level := args[0], args[1], args[2], args[3]
	readView, writeView := args[5], args[6]
	p.accessWrites[group] = append(p.accessWrites[group], writeView)
	p.rules = append(p.rules, snmpRule("access", group, model, level, context, readView, writeView))
}

// createUser records `createUser [-e ENGINEID] NAME [AUTHPROTO AUTHPASS
// [PRIVPROTO [PRIVPASS]]]`. The two passphrases are the most sensitive bytes
// on the host and are read only to know that they are there: neither is
// stored, and the level they imply is all that survives.
func (p *snmpParse) createUser(args []string) {
	if len(args) >= 2 && strings.EqualFold(args[0], "-e") {
		args = args[2:]
	}
	if len(args) == 0 {
		return
	}
	u := p.user(args[0])
	switch {
	case len(args) >= 4:
		u.authProto, u.privProto, u.keyLevel = args[1], args[3], "priv"
	case len(args) >= 2:
		u.authProto, u.keyLevel = args[1], "auth"
	default:
		u.keyLevel = "noauth"
	}
}

// roleUser records `rouser|rwuser [-s SECMODEL] NAME [noauth|auth|priv …]`.
// net-snmp's own default when the level is omitted is auth, so that is what
// is recorded — never noauth, which would understate the host's posture.
func (p *snmpParse) roleUser(args []string) {
	if len(args) >= 2 && strings.EqualFold(args[0], "-s") {
		args = args[2:]
	}
	if len(args) == 0 {
		return
	}
	u := p.user(args[0])
	u.accessLevel = "auth"
	if len(args) > 1 {
		switch strings.ToLower(args[1]) {
		case "noauth", "auth", "priv":
			u.accessLevel = strings.ToLower(args[1])
		}
	}
}

// user returns the accumulator for name, remembering first-seen order so the
// sort that follows is over a slice and never over a map.
func (p *snmpParse) user(name string) *snmpUser {
	if u, ok := p.users[name]; ok {
		return u
	}
	u := &snmpUser{name: name}
	p.users[name] = u
	p.userNames = append(p.userNames, name)
	return u
}

// agentAddress records every listen spec of an `agentaddress` directive. One
// directive may carry several specs separated by commas.
func (p *snmpParse) agentAddress(args []string) {
	for _, arg := range args {
		for _, spec := range strings.Split(arg, ",") {
			if spec = strings.TrimSpace(spec); spec != "" {
				p.agents = append(p.agents, spec)
			}
		}
	}
}

// includeFile follows `includeFile PATH` in place. R55/R75: a target outside
// the collector's declaration is RECORDED and never touched — the guard would
// refuse the read, and asking it through declared() keeps the question itself
// from counting as a violation.
func (p *snmpParse) includeFile(args []string, depth int) {
	if len(args) == 0 {
		return
	}
	target := path.Clean(args[0])
	if !declared(p.a, target) {
		p.undeclared = append(p.undeclared, target)
		return
	}
	p.readFile(target, depth+1)
}

// includeDir follows `includeDir DIRECTORY` in place. net-snmp reads the
// directory's *.conf files, so that glob — not the bare directory — is what
// the declaration has to cover.
func (p *snmpParse) includeDir(args []string, depth int) {
	if len(args) == 0 {
		return
	}
	pattern := strings.TrimSuffix(path.Clean(args[0]), "/") + snmpIncludeSuffix
	if !declared(p.a, pattern) {
		p.undeclared = append(p.undeclared, pattern)
		return
	}
	matches, err := p.a.Glob(pattern)
	if err != nil {
		p.fail(collect.ErrorEnv("glob " + pattern + ": " + err.Error()))
		return
	}
	sort.Strings(matches)
	for _, m := range matches {
		p.readFile(m, depth+1)
	}
}

// resolveCom2secKinds decides ro vs rw for every com2sec-derived community.
// A com2sec line grants nothing by itself: the security name has to reach a
// group, and that group an access rule whose write view is a real view.
// Anything else — no group, no access rule, a write view of "none" — is read
// only, which is what net-snmp itself enforces.
func (p *snmpParse) resolveCom2secKinds() {
	for _, ref := range p.com2secRefs {
		if !p.secNameWrites(ref.secName) {
			continue
		}
		if rec, ok := p.communities[ref.index].(map[string]any); ok {
			rec["kind"] = "rw"
		}
	}
}

func (p *snmpParse) secNameWrites(secName string) bool {
	for _, g := range p.groups {
		if g.secName != secName {
			continue
		}
		for _, w := range p.accessWrites[g.name] {
			if w != "" && w != "-" && !strings.EqualFold(w, "none") {
				return true
			}
		}
	}
	return false
}

// versions reports which protocol versions the configuration enables. A
// rocommunity/rwcommunity directive is net-snmp shorthand that enables BOTH
// v1 and v2c, so a host that writes one has both; a com2sec only enables a
// version once a group names that model for its security name; v3 is enabled
// by the existence of a user, wherever it was defined. The names sort into
// v1, v2c, v3 lexically, which is also their protocol order.
func (p *snmpParse) versions() []any {
	on := map[string]bool{}
	if p.communityDirective {
		on["v1"], on["v2c"] = true, true
	}
	for _, g := range p.groups {
		if !p.com2secNames[g.secName] {
			continue
		}
		switch strings.ToLower(g.model) {
		case "v1":
			on["v1"] = true
		case "v2c", "v2":
			on["v2c"] = true
		}
	}
	if len(p.userNames) > 0 {
		on["v3"] = true
	}
	out := []any{}
	for _, v := range []string{"v1", "v2c", "v3"} {
		if on[v] {
			out = append(out, v)
		}
	}
	return out
}

// v3Users renders the users sorted by name. auth_proto and priv_proto are
// empty for a user known only from a rouser/rwuser line — the key material
// lives in the persistent state file, and an empty protocol says "not seen
// here", never "none configured". level prefers what the key material
// supports over the minimum an access line demands.
func (p *snmpParse) v3Users() []any {
	names := append([]string(nil), p.userNames...)
	sort.Strings(names)
	out := []any{}
	for _, n := range names {
		u := p.users[n]
		level := u.keyLevel
		if level == "" {
			level = u.accessLevel
		}
		if level == "" {
			level = "noauth"
		}
		out = append(out, map[string]any{
			"name":       u.name,
			"auth_proto": u.authProto,
			"priv_proto": u.privProto,
			"level":      level,
		})
	}
	return out
}

func (p *snmpParse) sortedFiles() []any {
	files := append([]string(nil), p.files...)
	sort.Strings(files)
	out := []any{}
	for _, f := range files {
		out = append(out, f)
	}
	return out
}

// complete reports whether every file the parse was told to read could be
// read. A host with no snmpd configuration at all read everything there was,
// so the parse is complete and the judged lists carry the story instead.
func (p *snmpParse) complete() bool {
	return p.readFailure == nil && len(p.undeclared) == 0
}

// judged is the envelope the three judged lists share when the configuration
// could not be seen in full, and nil when it could. A read that failed wins
// over an include that could not be followed: it names a privilege or an I/O
// problem, which is the more actionable of the two.
func (p *snmpParse) judged() *facts.Envelope {
	if p.readFailure != nil {
		return p.readFailure
	}
	if len(p.undeclared) > 0 {
		targets := append([]string(nil), p.undeclared...)
		sort.Strings(targets)
		e := collect.Absent("the configuration includes " + strings.Join(targets, ", ") +
			", which is outside this collector's declaration and was not read")
		return &e
	}
	if len(p.files) == 0 {
		e := collect.Absent("no snmpd configuration found (" + strings.Join(
			append(append(snmpCandidates(), snmpdConfDGlob), snmpStateFiles()...), ", ") + ")")
		return &e
	}
	return nil
}

// snmpRule builds one access_rules record. The seven fields are fixed, so
// each directive fills the ones that carry its meaning and leaves the rest
// empty:
//
//	com2sec  name = security name,  source = the address or range
//	group    name = group name,     sec_model = v1|v2c|usm, source = security name
//	view     name = view name,      sec_level = included|excluded, source = OID subtree
//	access   name = group name,     sec_model, sec_level, source = context,
//	         read_view, write_view
//
// A com2sec's community is NOT one of the fields, here or anywhere.
func snmpRule(kind, name, secModel, secLevel, source, readView, writeView string) map[string]any {
	return map[string]any{
		"kind":       kind,
		"name":       name,
		"sec_model":  secModel,
		"sec_level":  secLevel,
		"source":     source,
		"read_view":  readView,
		"write_view": writeView,
	}
}

// snmpSourceRestricted reports whether a community is bound to a source at
// all. "default" and the two any-address forms are how net-snmp spells "from
// anywhere", so they are no restriction; so is an absent source.
func snmpSourceRestricted(source string) bool {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "", "default", "0.0.0.0", "0.0.0.0/0", "::/0":
		return false
	}
	return true
}

// snmpIsSourceToken decides whether the token after the community in a
// ro/rwcommunity directive is the SOURCE. The alternatives are an option flag
// (-V VIEW) and an OID subtree, both of which would be read as a source
// restriction that does not exist.
//
// Confidence boundary (H-16): an OID is written with a leading dot, or as a
// bare dotted-numeric path. An IPv4 address is also dotted-numeric, so the
// two are told apart by component count — an address has exactly four, an OID
// written without its dot has some other number — and a CIDR, which carries a
// "/", is unambiguously a source. A hostname, a netgroup and "default" are
// not numeric and are always sources. A dotted-numeric OID that happens to
// have exactly four components (.1.3.6.1 written bare as "1.3.6.1") would be
// read as an address; net-snmp's own examples always write the leading dot,
// and misreading one as a source can only make a community look MORE
// restricted than it is in the evidence, never less — U-61 judges
// source_restricted, so the failure mode is a false FAIL a human reviews, not
// a false PASS.
func snmpIsSourceToken(tok string) bool {
	switch {
	case tok == "":
		return false
	case strings.HasPrefix(tok, "-"):
		return false
	case strings.HasPrefix(tok, "."):
		return false
	case strings.Contains(tok, "/"):
		return true
	case snmpDottedNumeric(tok) && strings.Count(tok, ".") != 3:
		return false
	}
	return true
}

func snmpDottedNumeric(tok string) bool {
	for _, r := range tok {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return tok != ""
}

// snmpStripComment removes everything from the first unquoted '#' onward.
// net-snmp treats '#' as a comment introducer wherever it appears on a line,
// so a trailing comment must never become a directive argument — a community
// string is measured by its length, and a phantom token would be measured too.
func snmpStripComment(line string) string {
	inQuote := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			inQuote = !inQuote
		case '#':
			if !inQuote {
				return line[:i]
			}
		}
	}
	return line
}

// snmpTokens splits a directive line on whitespace, honouring double quotes.
// Unlike a plain split it emits an EMPTY token for `""`, because net-snmp's
// VACM lines are positional and spell the default context that way: dropping
// it would shift every field of an `access` line by one.
func snmpTokens(line string) []string {
	var toks []string
	var cur strings.Builder
	inQuote, started := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inQuote = !inQuote
			started = true
		case (c == ' ' || c == '\t') && !inQuote:
			if started {
				toks = append(toks, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteByte(c)
			started = true
		}
	}
	if started {
		toks = append(toks, cur.String())
	}
	return toks
}
