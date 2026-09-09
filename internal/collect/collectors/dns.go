//go:build linux

package collectors

import (
	"context"
	"net/netip"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The DNS server configuration files and daemon binaries this collector knows
// how to find. Which server is RUNNING is services.dns.*; these are the
// persisted view.
const (
	bindDebianConf = "/etc/bind/named.conf"
	bindRhelConf   = "/etc/named.conf"
	// The bind-chroot package's copy. It is declared because it is the file a
	// chrooted named actually loads, and a host carrying only that one would
	// otherwise read as "no DNS server" while it serves zones.
	bindChrootConf = "/var/named/chroot/etc/named.conf"
	unboundConf    = "/etc/unbound/unbound.conf"

	namedBin   = "/usr/sbin/named"
	unboundBin = "/usr/sbin/unbound"

	etcOSRelease    = "/etc/os-release"
	usrLibOSRelease = "/usr/lib/os-release"
)

// maxIncludeExpansions caps how many fragments ONE run inlines, however they
// are reached. Ruling L-58: maxIncludeDepth bounds a single chain and does not
// bound the work, because L-18/L-54 give an included fragment's statements to
// the enclosing block and therefore let the same file be inlined once per PATH
// that reaches it — a fragment that includes the next one twice doubles the
// token stream at every level, so the seven levels the depth cap allows are
// 2^7 re-reads of the deepest one. A configuration past this cap is a
// construct outside the model: it counts in dns.unmodelled and the judged
// leaves step back, rather than being answered from the part of the chain that
// happened to fit.
const maxIncludeExpansions = 64

// dnsImpl is one modelled DNS server: the configuration files it is
// recognised by, in probe order, and the binaries whose presence proves the
// package is installed rather than merely left behind (Ruling L-3, the 2I
// IR-7 lesson). The order of the table is the order a host carrying more than
// one is resolved in.
type dnsImpl struct {
	name  string
	confs []string
	bins  []string
}

var dnsImpls = []dnsImpl{
	{"bind", []string{bindDebianConf, bindRhelConf, bindChrootConf}, []string{namedBin}},
	{"unbound", []string{unboundConf}, []string{unboundBin}},
}

var dnsCollector = collect.Collector{
	Name: "dns",
	Declare: collect.Declaration{
		// The include targets a stock chain names on either distribution, and
		// nothing else. A zone's own file is NEVER read (Ruling L-17), so no
		// zone directory appears here; an include outside this list is
		// recorded with its path and left alone (Ruling L-18).
		Reads: []string{
			bindDebianConf, "/etc/bind/named.conf.*", "/etc/bind/*.conf",
			bindRhelConf, "/etc/named/*.conf", "/etc/named.rfc1912.zones",
			"/etc/named.root.key", "/etc/named/*.zones",
			"/etc/crypto-policies/back-ends/bind.config", bindChrootConf,
			unboundConf,
			etcOSRelease, usrLibOSRelease,
			namedBin, unboundBin,
		},
		// Needs: "none" — D14/Ruling L-2 forbid invoking the daemon, so there
		// is no `named-checkconf` here and no version fact. named.conf is
		// world-readable on both distributions, and one that is not is
		// reported denied through C3 rather than wrapped as a privilege
		// failure (Ruling L-7).
		Needs: "none",
	},
	Run: runDns,
}

// dnsJudgedKeys are the leaves a control judges, as opposed to the evidence
// leaves (implementation, config_files, parse_complete, unmodelled) that stay
// ok whatever the parse found. Ruling L-4: they degrade TOGETHER — a file that
// could not be read, a read cut at the cap or a construct outside the model
// makes every one of them carry that story.
var dnsJudgedKeys = []string{
	"dns.options.allow_transfer",
	"dns.options.allow_update",
	"dns.zones",
}

// dnsUnsetTransferReason is the answer when nothing sets allow-transfer on a
// build this collector does not know. Ruling L-16: BIND 9.20 turned outgoing
// transfers off by default, so the same file means opposite things on either
// side of that release and neither verdict may be guessed.
const dnsUnsetTransferReason = "allow-transfer is not set and the BIND default depends on the " +
	"version (any before 9.20, none from 9.20); set it explicitly"

// The kinds of element an address match list carries. Everything but "any"
// restricts SOMETHING; "any" is the one that lets every client through, which
// is what the transfer and update verdicts turn on.
const (
	dnsElemAny = iota
	dnsElemNone
	dnsElemLocalhost
	dnsElemLocalnets
	dnsElemAddress
	dnsElemKey
	dnsElemACL
	dnsElemNested
)

// dnsElem is one element of an address match list: the text as the file wrote
// it, whether it was negated, and what kind of thing it names.
type dnsElem struct {
	raw     string
	name    string // the ACL or key name, when it names one
	kind    int
	negated bool
}

// dnsAuthoritative names the zone types this host serves its own copy of, and
// therefore the ones an allow-transfer decides the transferability of. Ruling
// L-53 turns an undeterminable default into an absence of the whole list only
// for these — U-50 judges exactly them, and a hint, forward, stub or redirect
// zone carries nothing an operator would notice a transfer of.
//
// The residual is deliberate and narrow: on a build whose default this
// collector does not know, a SECONDARY (slave) zone — or any other type
// outside this table — is published with no transfer_restricted field at all,
// because there is no honest bool for it there either and inventing one is the
// guess Ruling L-16 exists to refuse. Nothing reads it: U-50 filters to these
// types in its `where`, which runs before the `require` that names the field.
var dnsAuthoritative = map[string]bool{"primary": true, "master": true}

// dnsZone is one zone statement, with the two lists it may set of its own.
type dnsZone struct {
	name  string
	ztype string
	file  string

	transfer    []dnsElem
	transferSet bool
	update      []dnsElem
	updateSet   bool
	// updatePolicy records that the zone carries an update-policy statement.
	// Only its PRESENCE is modelled: the rules inside it grant per-name
	// updates to named identities, which is a restriction whatever they say.
	updatePolicy bool
}

// runDns publishes the dns keys from configuration files alone: D14 forbids
// invoking the daemon, so nothing here runs named-checkconf and no version is
// derived.
//
// C3: a configuration file that EXISTS but cannot be read is the answer for
// every value it could set — never the daemon's compiled default. A host with
// no DNS server at all cannot be said to restrict zone transfers, so the
// judged leaves are absent (→ MANUAL) while the evidence leaves stay ok and
// the run stays complete (Ruling L-7).
func runDns(_ context.Context, a collect.Access, b *collect.Builder) error {
	p := &dnsParse{a: a, seen: map[string]bool{}, acls: map[string][]dnsElem{}}
	p.detect()
	p.publish(b)
	return nil
}

// dnsParse accumulates what this host's DNS configuration says. impl is the
// implementation the files and binaries agree on; files is every file whose
// content reached the parse, in read order.
type dnsParse struct {
	a        collect.Access
	impl     string
	mainFile string
	leftover string // a conffile whose daemon binary is not installed

	files     []string
	seen      map[string]bool
	truncated []string

	// readFailure is the first read that could not answer; unmodelled lists
	// every construct outside the model, each naming the file and the
	// construct; notRead lists the includes the declaration does not cover.
	// Any of the three means the judged leaves cannot be answered.
	readFailure *facts.Envelope
	unmodelled  []string
	notRead     []string
	undefACL    map[string]bool
	// unknownTransfer names the primary zones whose transfer default could not
	// be determined (Ruling L-53). It absents dns.zones alone, never the other
	// judged leaves.
	unknownTransfer []string
	// expanded counts the fragments this run has inlined, across every chain
	// (Ruling L-58): the depth cap bounds one path, this bounds the work.
	expanded int

	acls  map[string][]dnsElem
	zones []dnsZone

	optTransfer    []dnsElem
	optTransferSet bool
	optUpdate      []dnsElem
	optUpdateSet   bool

	// The build the unset allow-transfer default is read from (Ruling L-16).
	osID, osVersion string

	records []any
}

// detect names the implementation this host's files and binaries agree on and
// parses its configuration. Ruling L-3: a configuration file counts only when
// the daemon's binary is installed too — dpkg keeps the conffile after
// `apt remove`, and judging a removed package's file is a confidently wrong
// verdict either way.
func (p *dnsParse) detect() {
	for _, im := range dnsImpls {
		conf, ok := p.present(im)
		if !ok {
			continue
		}
		p.impl, p.mainFile = im.name, conf
		break
	}
	switch p.impl {
	case "":
		p.impl = "none"
	case "unbound":
		// unbound is a resolver: it serves no authoritative zones, so there is
		// nothing in its configuration this collector would be entitled to
		// judge. The file is recorded as the evidence that named the
		// implementation and is never opened — so the source these leaves cite
		// is a path this collector STAT-ed rather than read, which the registry
		// description states in as many words.
		p.record(p.mainFile, false)
	case "bind":
		p.readBuild()
		p.readChain()
		p.resolve()
	}
}

// present reports the first configuration file of this server that is on disk,
// and whether the package's binary is installed beside it.
//
// Presence is a stat, not a read: a named.conf that exists but cannot be read
// still names this host a bind host, and C3 then answers every value with the
// read's own failure rather than with "no DNS server here".
func (p *dnsParse) present(im dnsImpl) (string, bool) {
	for _, c := range im.confs {
		if !pathPresent(p.a, c) {
			continue
		}
		if !anyPresent(p.a, im.bins) {
			p.noteLeftover(c, im.bins)
			return "", false
		}
		return c, true
	}
	return "", false
}

// noteLeftover records a configuration file whose daemon binary is not
// installed. The FIRST one found is kept, so the reason is stable.
func (p *dnsParse) noteLeftover(conf string, bins []string) {
	if p.leftover == "" {
		p.leftover = conf + " is present but " + strings.Join(bins, " or ") +
			" is not: configuration of a removed package"
	}
}

// readBuild reads ID and VERSION_ID out of the first os-release file that
// answers. Ruling L-16: an unset allow-transfer means "any" on BIND 9.16/9.18
// and "none" from 9.20, and the distribution release is the only evidence on
// disk for which of the two this host runs.
func (p *dnsParse) readBuild() {
	for _, f := range []string{etcOSRelease, usrLibOSRelease} {
		data, _, err := p.a.ReadFile(f, readLimit)
		if err != nil {
			continue
		}
		for _, line := range splitLines(data) {
			k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok {
				continue
			}
			v = strings.Trim(v, `"'`)
			switch k {
			case "ID":
				p.osID = strings.ToLower(v)
			case "VERSION_ID":
				p.osVersion = v
			}
		}
		return
	}
}

// defaultTransferAny reports whether this build's BIND transfers to anyone
// when nothing sets allow-transfer. The table is the releases muster supports
// whose BIND is 9.16 or 9.18; every other build — including an os-release that
// could not be read — is unknown, and the verdict is refused rather than
// guessed (Ruling L-16).
func (p *dnsParse) defaultTransferAny() bool {
	switch p.osID {
	case "ubuntu":
		return p.osVersion == "22.04" || p.osVersion == "24.04"
	case "debian":
		return p.osVersion == "12"
	case "rhel", "rocky", "almalinux":
		return p.osVersion == "9" || strings.HasPrefix(p.osVersion, "9.")
	}
	return false
}

// buildName is how a reason names the build the default came from.
func (p *dnsParse) buildName() string {
	if p.osID == "" {
		return "this host"
	}
	return strings.TrimSpace(p.osID + " " + p.osVersion)
}

// readChain reads named.conf and tokenises the whole include chain into one
// stream, so an included fragment's statements belong to the block that
// included it (Ruling L-18).
func (p *dnsParse) readChain() {
	data, meta, err := p.a.ReadFile(p.mainFile, readLimit)
	if err != nil {
		p.fail(readErrorEnv(p.mainFile, err))
		return
	}
	p.record(p.mainFile, meta.Truncated)
	s := &dnsStream{p: p, frames: []dnsFrame{{toks: dnsTokenize(data), file: p.mainFile}}}
	p.parseTop(s)
}

// record notes a file whose content reached the parse, once however it was
// reached, and whether the read primitive cut it at the cap.
func (p *dnsParse) record(file string, truncated bool) {
	file = path.Clean(file)
	if p.seen[file] {
		return
	}
	p.seen[file] = true
	p.files = append(p.files, file)
	if truncated {
		p.truncated = append(p.truncated, file)
	}
}

// fail records the first read that could not answer. The first is kept rather
// than the worst, so the reason names the file the collector reached first in
// its own fixed order and the same input yields the same reason.
func (p *dnsParse) fail(e facts.Envelope) {
	if p.readFailure == nil {
		p.readFailure = &e
	}
}

func (p *dnsParse) noteUnmodelled(file, what string) {
	if file == "" {
		file = p.mainFile
	}
	p.unmodelled = append(p.unmodelled, file+": "+what)
}

// noteUndefinedACL records an address match list element that names an ACL
// nothing in the chain defines, once per name. What it would have matched is
// unknowable from the files, so a verdict drawn from the elements around it
// would be a verdict about a configuration this host does not have. It names
// no file: resolution happens after the whole chain is parsed, and which
// fragment carried the reference is no longer the useful half of the reason.
func (p *dnsParse) noteUndefinedACL(name string) {
	if p.undefACL == nil {
		p.undefACL = map[string]bool{}
	}
	if p.undefACL[name] {
		return
	}
	p.undefACL[name] = true
	p.unmodelled = append(p.unmodelled, "an address match list names "+name+
		", which no acl statement in this chain defines")
}

// noteUnread records an include this collector's declaration does not cover.
// It is BOTH unmodelled and an incomplete parse: the configuration told the
// collector to read a file and the collector did not, so what that file sets
// is unknown as surely as if it could not be opened.
func (p *dnsParse) noteUnread(file, target string) {
	p.notRead = append(p.notRead, target)
	p.noteUnmodelled(file, "include "+target+
		" is outside this collector's declaration and was not read")
}

// --- the tokenizer ------------------------------------------------------

// dnsToken is one token of a named.conf: a brace or a semicolon (punct), a
// quoted string, or a bare word. The quoted flag matters because a quoted
// "include" is a name, not the include statement.
type dnsToken struct {
	text   string
	quoted bool
	punct  bool
}

// dnsTokenize splits a named.conf into tokens. named's own lexer recognises
// three comment syntaxes — "//" and "#" to end of line and "/* … */" spanning
// lines — and a double-quoted string in which none of them, and no brace or
// semicolon, is a token.
func dnsTokenize(data []byte) []dnsToken {
	s := string(data)
	var out []dnsToken
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == '#' || (c == '/' && i+1 < len(s) && s[i+1] == '/'):
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			i += 2
			for i+1 < len(s) && !(s[i] == '*' && s[i+1] == '/') {
				i++
			}
			if i+1 < len(s) {
				i += 2
			} else {
				i = len(s)
			}
		case c == '"':
			i++
			start := i
			for i < len(s) && s[i] != '"' {
				i++
			}
			out = append(out, dnsToken{text: s[start:i], quoted: true})
			if i < len(s) {
				i++
			}
		case c == '{' || c == '}' || c == ';':
			out = append(out, dnsToken{text: string(c), punct: true})
			i++
		default:
			start := i
			for i < len(s) && !dnsWordEnd(s, i) {
				i++
			}
			if i == start { // defensive: never spin on one byte
				i++
				continue
			}
			out = append(out, dnsToken{text: s[start:i]})
		}
	}
	return out
}

// dnsWordEnd reports whether a bare word ends at this byte. A single "/" is
// part of the word — a prefix length is written 192.0.2.0/24 — while "//" and
// "/*" start a comment and end it.
func dnsWordEnd(s string, i int) bool {
	switch s[i] {
	case ' ', '\t', '\r', '\n', '{', '}', ';', '"', '#':
		return true
	case '/':
		return i+1 < len(s) && (s[i+1] == '/' || s[i+1] == '*')
	}
	return false
}

// --- the token stream ---------------------------------------------------

// dnsFrame is one file's tokens and how far the parse has read into them.
type dnsFrame struct {
	toks []dnsToken
	i    int
	file string
}

// dnsStream is the token stream the parser reads, with the include chain
// spliced into it. Ruling L-18: an "include" is expanded WHERE IT STANDS, so
// the fragment's statements belong to the enclosing block — stock RHEL 9
// includes the crypto policy inside options {} — and the expansion happens
// here rather than in any one statement's parser, so it works at any depth.
type dnsStream struct {
	p      *dnsParse
	frames []dnsFrame
	pushed *dnsToken
}

// raw returns the next token without expanding includes, popping frames that
// are exhausted.
func (s *dnsStream) raw() (dnsToken, bool) {
	for len(s.frames) > 0 {
		f := &s.frames[len(s.frames)-1]
		if f.i < len(f.toks) {
			t := f.toks[f.i]
			f.i++
			return t, true
		}
		s.frames = s.frames[:len(s.frames)-1]
	}
	return dnsToken{}, false
}

func (s *dnsStream) next() (dnsToken, bool) {
	if s.pushed != nil {
		t := *s.pushed
		s.pushed = nil
		return t, true
	}
	for {
		t, ok := s.raw()
		if !ok {
			return dnsToken{}, false
		}
		if !t.punct && !t.quoted && t.text == "include" {
			s.include()
			continue
		}
		return t, true
	}
}

// unread pushes one token back, so a parser that had to look at it can leave
// it for the loop above.
func (s *dnsStream) unread(t dnsToken) { s.pushed = &t }

// file is the file the stream is currently reading, for a reason that has to
// name it.
func (s *dnsStream) file() string {
	if len(s.frames) == 0 {
		return ""
	}
	return s.frames[len(s.frames)-1].file
}

// word is the next token's text when it is a word, and "" when the next token
// is punctuation — which is left in the stream, so a statement that ends
// early does not swallow the brace that closes its block.
func (s *dnsStream) word() string {
	t, ok := s.next()
	if !ok {
		return ""
	}
	if t.punct {
		s.unread(t)
		return ""
	}
	return t.text
}

// include expands one include statement in place. The terminating ";" is
// deliberately NOT consumed: it stays in the parent frame behind the
// fragment's tokens, where every loop treats it as the separator it is —
// which is also what named does with a fragment whose last statement is
// unterminated.
func (s *dnsStream) include() {
	from := s.file()
	t, ok := s.raw()
	if !ok || t.punct {
		s.p.noteUnmodelled(from, "an include statement that names no file")
		return
	}
	target := strings.TrimSpace(t.text)
	if target == "" {
		s.p.noteUnmodelled(from, "an include statement that names no file")
		return
	}
	clean := path.Clean(target)
	if len(s.frames) >= maxIncludeDepth {
		s.p.fail(collect.ErrorEnv("include nesting deeper than " +
			strconv.Itoa(maxIncludeDepth) + " levels at " + from))
		return
	}
	// R55/Ruling L-5: the target is asked of the declaration through the
	// guard's own Allowed probe, so an include outside it is RECORDED with its
	// path and never touched — muster does not read a path a change-control
	// reviewer never approved.
	if !declared(s.p.a, clean) {
		s.p.noteUnread(from, clean)
		return
	}
	// Ruling L-54: the guard is per include CHAIN, not per run. L-18 gives an
	// included fragment's statements to the ENCLOSING block, so the same
	// fragment included from two different scopes means two different things
	// and named reads it both times; skipping the second would report a zone
	// as restricted while the running server transfers it to anyone. What must
	// still be refused is a file that is already OPEN above this point — a
	// cycle, which would otherwise only stop at the depth cap.
	if s.open(clean) {
		s.p.noteUnmodelled(from, "include "+clean+
			" is already open in this include chain: a cycle, which was not followed")
		return
	}
	// Ruling L-58: the run-wide expansion cap, checked here so the declaration
	// guard and the cycle guard keep answering for their own cases first. It
	// is what bounds the WORK — the per-chain guard admits one inlining per
	// path, and paths multiply.
	if s.p.expanded >= maxIncludeExpansions {
		s.p.noteUnmodelled(from, "include "+clean+" was not expanded: this run has already inlined "+
			strconv.Itoa(maxIncludeExpansions)+" fragments, the cap on one configuration's include expansion")
		return
	}
	data, meta, err := s.p.a.ReadFile(clean, readLimit)
	if err != nil {
		// An include names a file named itself refuses to start without, so a
		// missing one is a failure, not a fragment to skip.
		s.p.fail(readErrorEnv(clean, err))
		return
	}
	s.p.record(clean, meta.Truncated)
	s.p.expanded++
	s.frames = append(s.frames, dnsFrame{toks: dnsTokenize(data), file: clean})
}

// open reports whether a file is already being read further up this include
// chain. Only the frames currently on the stack count: a fragment that was
// read and finished is not open, and including it again is legitimate.
func (s *dnsStream) open(file string) bool {
	for _, f := range s.frames {
		if f.file == file {
			return true
		}
	}
	return false
}

// skipStatement consumes the rest of a statement this model does not read,
// balancing braces so a block belonging to it goes with it. A "}" found at
// depth zero closes the ENCLOSING block and is left in the stream.
func (s *dnsStream) skipStatement() {
	depth := 0
	for {
		t, ok := s.next()
		if !ok {
			return
		}
		if !t.punct {
			continue
		}
		switch t.text {
		case "{":
			depth++
		case "}":
			if depth == 0 {
				s.unread(t)
				return
			}
			depth--
		case ";":
			if depth == 0 {
				return
			}
		}
	}
}

// skipBlock consumes tokens up to the "}" that closes a block already opened.
func (s *dnsStream) skipBlock() {
	for depth := 1; depth > 0; {
		t, ok := s.next()
		if !ok {
			return
		}
		if !t.punct {
			continue
		}
		switch t.text {
		case "{":
			depth++
		case "}":
			depth--
		}
	}
}

// openBlock advances to the "{" that opens this statement's block, reporting
// false when the statement (or the file) ends before one appears.
func (s *dnsStream) openBlock() bool {
	for {
		t, ok := s.next()
		if !ok {
			return false
		}
		if !t.punct {
			continue
		}
		switch t.text {
		case "{":
			return true
		case ";":
			return false
		case "}":
			s.unread(t)
			return false
		}
	}
}

// --- the parser ---------------------------------------------------------

// parseTop reads the top-level statements. Three kinds are modelled —
// options, acl and zone. A view is the one that is REFUSED rather than
// ignored: its zones are per-client configurations this collector does not
// model, and reading the server as if it had none would be an over-claim
// (H-16). Every other statement is neutral and its block is consumed.
func (p *dnsParse) parseTop(s *dnsStream) {
	for {
		t, ok := s.next()
		if !ok {
			return
		}
		if t.punct {
			switch t.text {
			case ";":
			case "{":
				s.skipBlock()
			case "}":
				p.noteUnmodelled(s.file(), "a closing brace with no statement open")
			}
			continue
		}
		if t.quoted {
			s.skipStatement()
			continue
		}
		switch strings.ToLower(t.text) {
		case "options":
			if s.openBlock() {
				p.parseOptions(s)
			}
		case "acl":
			p.parseACL(s)
		case "zone":
			p.parseZone(s)
		case "view":
			p.noteUnmodelled(s.file(), "a view statement, whose per-client zones this collector does not model")
			s.skipStatement()
		default:
			s.skipStatement()
		}
	}
}

// parseOptions reads the two lists of the options block. Everything else in it
// — including the crypto-policy fragment RHEL 9 includes here, which sets
// disable-algorithms and disable-ds-digests — is neutral.
func (p *dnsParse) parseOptions(s *dnsStream) {
	for {
		t, ok := s.next()
		if !ok {
			return
		}
		if t.punct {
			if t.text == "}" {
				return
			}
			continue
		}
		switch strings.ToLower(t.text) {
		case "allow-transfer":
			if s.openBlock() {
				p.optTransfer, p.optTransferSet = p.parseAML(s), true
			}
		case "allow-update":
			if s.openBlock() {
				p.optUpdate, p.optUpdateSet = p.parseAML(s), true
			}
		default:
			s.skipStatement()
		}
	}
}

// parseACL reads one named address match list. The definition may sit after
// the references to it, which is why resolution is a second pass.
func (p *dnsParse) parseACL(s *dnsStream) {
	name := ""
	for {
		t, ok := s.next()
		if !ok {
			return
		}
		if t.punct {
			if t.text != "{" {
				return // malformed: no block
			}
			break
		}
		if name == "" {
			name = t.text
		}
	}
	elems := p.parseAML(s)
	if name != "" {
		// named compares acl names case-insensitively, so the table is keyed
		// on the folded name; the element keeps the spelling the file used,
		// because that is what a reason and a rendered list show.
		p.acls[strings.ToLower(name)] = elems
	}
}

// parseZone reads one zone statement: its name, its type, the file it names
// and the two lists it may set. Every other substatement is neutral.
func (p *dnsParse) parseZone(s *dnsStream) {
	var z dnsZone
	named := false
	for {
		t, ok := s.next()
		if !ok {
			return
		}
		if t.punct {
			if t.text != "{" {
				return // "zone "x";" has no block to read
			}
			break
		}
		if !named { // the first word is the name; a class follows it
			z.name, named = t.text, true
		}
	}
	for {
		t, ok := s.next()
		if !ok {
			break
		}
		if t.punct {
			if t.text == "}" {
				break
			}
			continue
		}
		switch strings.ToLower(t.text) {
		case "type":
			z.ztype = strings.ToLower(s.word())
		case "file":
			// Ruling L-17: recorded verbatim and never opened. Every real zone
			// file lives outside this collector's declaration, and asking the
			// guard about it would make dns.zones absent on every BIND host.
			z.file = s.word()
		case "allow-transfer":
			if s.openBlock() {
				z.transfer, z.transferSet = p.parseAML(s), true
			}
		case "allow-update":
			if s.openBlock() {
				z.update, z.updateSet = p.parseAML(s), true
			}
		case "update-policy":
			z.updatePolicy = true
			s.skipStatement()
		default:
			s.skipStatement()
		}
	}
	p.zones = append(p.zones, z)
}

// parseAML reads an address match list, the "{" already consumed. A list
// nested inside another is the one element this model refuses: resolving it
// needs the negation semantics of the enclosing list, and a verdict drawn
// from the elements around it would be a verdict about a different list.
func (p *dnsParse) parseAML(s *dnsStream) []dnsElem {
	elems := []dnsElem{}
	for {
		t, ok := s.next()
		if !ok {
			return elems
		}
		if t.punct {
			switch t.text {
			case "}":
				return elems
			case "{":
				p.noteUnmodelled(s.file(), "a nested address match list, whose elements this collector does not resolve")
				s.skipBlock()
				elems = append(elems, dnsElem{raw: "{ … }", kind: dnsElemNested})
			}
			continue
		}
		elems = append(elems, p.amlElement(s, t))
	}
}

// amlElement classifies one element. A negation is recognised in both
// spellings named accepts — "!name" and "! name".
func (p *dnsParse) amlElement(s *dnsStream, t dnsToken) dnsElem {
	body, neg := t.text, false
	if body == "!" {
		neg, body = true, s.word()
	} else if rest, ok := strings.CutPrefix(body, "!"); ok {
		neg, body = true, rest
	}
	e := dnsElem{negated: neg}
	if !t.quoted && strings.EqualFold(body, "key") {
		e.name = s.word()
		e.kind, e.raw = dnsElemKey, "key "+e.name
	} else {
		e.raw = body
		switch strings.ToLower(body) {
		case "any":
			e.kind = dnsElemAny
		case "none":
			e.kind = dnsElemNone
		case "localhost":
			e.kind = dnsElemLocalhost
		case "localnets":
			e.kind = dnsElemLocalnets
		default:
			if dnsIsAddress(body) {
				e.kind = dnsElemAddress
			} else {
				e.kind, e.name = dnsElemACL, body
			}
		}
	}
	if neg {
		e.raw = "!" + e.raw
	}
	return e
}

// dnsIsAddress reports whether an element is a literal address or prefix
// rather than the name of an ACL.
func dnsIsAddress(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

// --- resolution ---------------------------------------------------------

// resolve turns the parsed statements into the published zone records. It runs
// after the whole chain is parsed, so an ACL defined below its first reference
// resolves, and it is where an ACL nothing defines is counted.
func (p *dnsParse) resolve() {
	sort.SliceStable(p.zones, func(i, j int) bool { return p.zones[i].name < p.zones[j].name })
	p.records = []any{}
	for _, z := range p.zones {
		p.records = append(p.records, p.zoneRecord(z))
	}
	// The options-level lists are resolved even when no zone inherits them, so
	// an undefined ACL named only there is still counted.
	if p.optTransferSet {
		p.listOpen(p.optTransfer, map[string]bool{})
	}
	if p.optUpdateSet {
		p.listOpen(p.optUpdate, map[string]bool{})
	}
}

// listOpen reports whether an address match list lets ANY client through. A
// NEGATED element restricts nothing by itself — "{ !192.0.2.1; any; }" still
// serves everyone else — so only the positive elements are read, and "any" is
// the only one of them that opens the list.
func (p *dnsParse) listOpen(elems []dnsElem, seen map[string]bool) bool {
	for _, e := range elems {
		if e.negated {
			continue
		}
		switch e.kind {
		case dnsElemAny:
			return true
		case dnsElemACL:
			ref, ok := p.acls[strings.ToLower(e.name)]
			if !ok {
				p.noteUndefinedACL(e.name)
				continue
			}
			if seen[strings.ToLower(e.name)] {
				continue // an acl that names itself, directly or in a cycle
			}
			seen[strings.ToLower(e.name)] = true
			if p.listOpen(ref, seen) {
				return true
			}
		}
	}
	return false
}

// zoneRecord is one zone as the fact carries it. The effective list is the
// zone's own when it sets one and the options level's otherwise.
//
// name, type and update_restricted are on every record a published list
// carries, and so is transfer_restricted — EXCEPT on a zone outside
// dnsAuthoritative (a secondary, hint, stub, forward or redirect zone) whose
// build default is unknown, which no control reads. A record has no envelope
// inside it, and a control that reads a field a record does not have is an
// internal ERROR rather than an absence, so for the primary and master zones a
// transfer control does judge, a question with no answer is refused at the
// LEAF (Ruling L-53) rather than by omitting the field the clause names. file,
// allow_transfer and allow_update are evidence no control requires and are
// left out when there is nothing to record: an empty allow-transfer list is
// legal and renders as "", which must stay distinct from "nothing set one".
func (p *dnsParse) zoneRecord(z dnsZone) map[string]any {
	rec := map[string]any{"name": z.name, "type": z.ztype}
	if z.file != "" {
		rec["file"] = z.file
	}

	transfer, transferSet := z.transfer, z.transferSet
	if !transferSet {
		transfer, transferSet = p.optTransfer, p.optTransferSet
	}
	switch {
	case transferSet:
		if r := dnsRender(transfer); !oversized(r) {
			rec["allow_transfer"] = r
		}
		rec["transfer_restricted"] = !p.listOpen(transfer, map[string]bool{})
	case p.defaultTransferAny():
		// Ruling L-16: nothing sets the list and this build's default is any.
		rec["transfer_restricted"] = false
	case dnsAuthoritative[z.ztype]:
		// Ruling L-53: nothing sets the list and the build is unknown, so
		// there is no honest bool to put here — and a record cannot carry an
		// "unknown", because a control that reads a field a record does not
		// have is an internal ERROR rather than the MANUAL Ruling L-16 asks
		// for. The zone is named instead, and publish absents the WHOLE leaf.
		p.unknownTransfer = append(p.unknownTransfer, z.name)
	}

	update, updateSet := z.update, z.updateSet
	if !updateSet {
		update, updateSet = p.optUpdate, p.optUpdateSet
	}
	if updateSet {
		if r := dnsRender(update); !oversized(r) {
			rec["allow_update"] = r
		}
	}
	switch {
	case z.updatePolicy:
		// update-policy grants named identities per-name updates, which is a
		// restriction whatever the rules say; named refuses it beside an
		// allow-update anyway.
		rec["update_restricted"] = true
	case !updateSet:
		rec["update_restricted"] = true // the default is none in every version
	default:
		rec["update_restricted"] = !p.listOpen(update, map[string]bool{})
	}
	return rec
}

// dnsRender is an address match list as a string: the elements as the file
// wrote them, in file order, separated the way named separates them.
func dnsRender(elems []dnsElem) string {
	parts := make([]string, 0, len(elems))
	for _, e := range elems {
		parts = append(parts, e.raw)
	}
	return strings.Join(parts, "; ")
}

// --- publication --------------------------------------------------------

func (p *dnsParse) publish(b *collect.Builder) {
	src := filesSource(p.files)
	cut := len(p.truncated) > 0

	impl := collect.OK(p.impl, p.implSource())
	switch {
	case p.impl == "none" && p.leftover != "":
		// Name the file, so a reader can see a leftover to purge rather than a
		// configuration anything was judged by (IR-7).
		impl.Reason = "no DNS server on this host: " + p.leftover
	case p.impl == "unbound":
		impl.Reason = "unbound is a caching resolver; it serves no authoritative zones, " +
			"so " + unboundConf + " is recorded as evidence and is not parsed"
	}
	b.Set("dns.implementation", impl)

	// Ruling L-49 (C3): a main configuration file that exists but could not be
	// read is not an empty list of configuration files — it is a file this
	// collector knows is there and could not open, and the leaf says so with
	// the read's own status. A fragment that failed leaves the files that DID
	// answer as evidence.
	files := withTruncation(collect.OK(dnsList(p.sortedFiles()), src), cut)
	if p.readFailure != nil && len(p.files) == 0 {
		files = *p.readFailure
	}
	b.Set("dns.config_files", files)
	b.Set("dns.parse_complete", collect.OK(p.complete(), src))
	b.Set("dns.unmodelled", collect.OK(len(p.unmodelled), src))

	if e := p.judged(); e != nil {
		for _, k := range dnsJudgedKeys {
			b.Set(k, *e)
		}
		return
	}
	if p.impl == "unbound" {
		reason := "unbound serves no authoritative zones, so it has no allow-transfer or " +
			"allow-update of this shape"
		b.Set("dns.options.allow_transfer", collect.Absent(reason))
		b.Set("dns.options.allow_update", collect.Absent(reason))
		zones := collect.OK([]any{}, src)
		zones.Reason = reason
		b.Set("dns.zones", zones)
		return
	}
	b.Set("dns.options.allow_transfer", p.optionTransfer(src))
	b.Set("dns.options.allow_update", p.optionUpdate(src))
	// Ruling L-53: the absence is published HERE rather than through judged(),
	// whose envelope reaches all three leaves. dns.options.allow_update is
	// perfectly knowable on a host with an unknown BIND build — unset is none
	// in every version — and must keep answering.
	if len(p.unknownTransfer) > 0 {
		b.Set("dns.zones", collect.Absent("allow-transfer is not set for zone "+
			strings.Join(p.unknownTransfer, ", ")+" and the BIND default depends on the "+
			"version (any before 9.20, none from 9.20); set it explicitly"))
		return
	}
	b.Set("dns.zones", collect.OK(p.records, src))
}

// complete reports whether every configuration file the parse was told to read
// could be read in full. A host with no DNS configuration at all read
// everything there was, so the parse is complete and the judged leaves carry
// that story instead. A construct outside the model is NOT a read failure — it
// counts in unmodelled and leaves this true — but an include the declaration
// does not cover IS one: the configuration named a file and it was not read.
func (p *dnsParse) complete() bool {
	return p.readFailure == nil && len(p.truncated) == 0 && len(p.notRead) == 0
}

// judged is the envelope every judged leaf shares when the configuration could
// not be seen or could not be modelled, and nil when it could. A read that
// failed wins over a cap and over an unmodelled construct: it names a
// privilege or an I/O problem, which is the more actionable of the three.
func (p *dnsParse) judged() *facts.Envelope {
	if p.readFailure != nil {
		return p.readFailure
	}
	if len(p.truncated) > 0 {
		e := collect.Absent("the configuration was cut at the read limit in " +
			strings.Join(p.truncated, ", ") + "; what is past the cap cannot be judged")
		return &e
	}
	if len(p.unmodelled) > 0 {
		e := collect.Absent("this configuration uses constructs outside the collector's model: " +
			strings.Join(p.unmodelled, "; "))
		return &e
	}
	if p.impl == "none" {
		reason := "no DNS server is installed on this host: none of " +
			strings.Join(dnsConfCandidates(), ", ") + " is present with its daemon binary"
		if p.leftover != "" {
			reason = "no DNS server is installed on this host: " + p.leftover
		}
		e := collect.Absent(reason)
		return &e
	}
	return nil
}

// optionTransfer is the options-level allow-transfer, or the ABSENCE that
// names the default it was not set against (Ruling L-16).
func (p *dnsParse) optionTransfer(src *facts.Source) facts.Envelope {
	if !p.optTransferSet {
		if p.defaultTransferAny() {
			return collect.Absent("options sets no allow-transfer; the BIND 9.16/9.18 build on " +
				p.buildName() + " defaults to any, so every zone that does not set its own list " +
				"may be transferred by anyone")
		}
		return collect.Absent(dnsUnsetTransferReason)
	}
	r := dnsRender(p.optTransfer)
	if oversized(r) {
		// The reason names the limit, never the value: the value is exactly
		// what must not be copied into the snapshot (M16).
		return collect.Absent("options allow-transfer: " + oversizedReason)
	}
	return collect.OK(r, src)
}

func (p *dnsParse) optionUpdate(src *facts.Source) facts.Envelope {
	if !p.optUpdateSet {
		return collect.Absent("options sets no allow-update; not set is none in every version")
	}
	r := dnsRender(p.optUpdate)
	if oversized(r) {
		return collect.Absent("options allow-update: " + oversizedReason)
	}
	return collect.OK(r, src)
}

func (p *dnsParse) implSource() *facts.Source {
	if p.mainFile != "" {
		return &facts.Source{Kind: "file", Path: p.mainFile}
	}
	return &facts.Source{Kind: "derived"}
}

func (p *dnsParse) sortedFiles() []string {
	files := append([]string(nil), p.files...)
	slices.Sort(files)
	return files
}

// dnsConfCandidates is every configuration file the collector looks for, in
// probe order — the list a reason names when it found none of them.
func dnsConfCandidates() []string {
	var c []string
	for _, im := range dnsImpls {
		c = append(c, im.confs...)
	}
	return c
}

// dnsList renders a string slice as the []any a list-valued fact carries,
// empty rather than nil so it serialises as "[]" (R50).
func dnsList(items []string) []any {
	out := []any{}
	for _, s := range items {
		out = append(out, s)
	}
	return out
}
