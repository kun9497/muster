//go:build linux

package collectors

import (
	"context"
	"regexp"
	"slices"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The mail transfer agent configuration files and binaries this collector
// knows how to find. Which MTA is RUNNING is services.mail.*; these are the
// persisted view.
const (
	postfixMainCf = "/etc/postfix/main.cf"
	sendmailCf    = "/etc/mail/sendmail.cf"
	exim4Conf     = "/etc/exim4/update-exim4.conf.conf"
	eximConf      = "/etc/exim/exim.conf"

	postfixBin     = "/usr/sbin/postfix"
	sendmailBin    = "/usr/sbin/sendmail.sendmail"
	sendmailMtaBin = "/usr/sbin/sendmail-mta"
	exim4Bin       = "/usr/sbin/exim4"
	eximBin        = "/usr/sbin/exim"
)

// mailImpl is one modelled MTA: the configuration files it is recognised by,
// in probe order, and the binaries whose presence proves the package is
// installed rather than merely left behind (Ruling L-3, the 2I IR-7 lesson).
// The order of the table is the order a host carrying more than one is
// resolved in.
type mailImpl struct {
	name  string
	confs []string
	bins  []string
}

var mailImpls = []mailImpl{
	{"postfix", []string{postfixMainCf}, []string{postfixBin}},
	// Debian's alternatives system installs the sendmail MTA as
	// /usr/sbin/sendmail-mta, a symlink; anyPresent counts a symlink as
	// present, which is exactly what Ruling L-20 needs here.
	{"sendmail", []string{sendmailCf}, []string{sendmailBin, sendmailMtaBin}},
	{"exim", []string{exim4Conf, eximConf}, []string{exim4Bin, eximBin}},
}

var mailCollector = collect.Collector{
	Name: "mail",
	Declare: collect.Declaration{
		Reads: []string{
			postfixMainCf, sendmailCf, exim4Conf, eximConf,
			postfixBin, sendmailBin, sendmailMtaBin, exim4Bin, eximBin,
		},
		// Needs: "none" — D14/Ruling L-2 forbid invoking the daemon, so
		// there is no postconf(1) here and no version fact. main.cf and
		// sendmail.cf are world-readable on both distributions, and one that
		// is not is reported denied through C3 rather than wrapped as a
		// privilege failure (Ruling L-7).
		Needs: "none",
	},
	Run: runMail,
}

// mailJudgedKeys are the leaves a control judges, as opposed to the evidence
// leaves (implementation, config_files) that stay ok whatever the parse
// found. They degrade TOGETHER: a file that could not be read, or a read cut
// at the cap, makes every one of them carry that story.
var mailJudgedKeys = []string{
	"mail.postfix.inet_interfaces",
	"mail.postfix.mynetworks",
	"mail.postfix.smtpd_relay_restrictions",
	"mail.postfix.smtpd_recipient_restrictions",
	"mail.postfix.disable_vrfy_command",
	"mail.postfix.authorized_submit_users",
	"mail.sendmail.privacy_options",
	"mail.expn_vrfy_restricted",
}

// postfixParam is one main.cf parameter this collector publishes, with the
// value postfix itself compiles in when the file does not set it. An unset
// parameter is ABSENT with that default NAMED — never the default published
// as a value — because what a control judges must be what the host's own
// configuration says, and a default that changes with the postfix release
// would otherwise read as evidence from this host.
type postfixParam struct {
	param string // main.cf parameter name
	key   string // fact key
	def   string // the compiled default, as the reason states it
}

var postfixParams = []postfixParam{
	{"inet_interfaces", "mail.postfix.inet_interfaces", "all"},
	{"mynetworks", "mail.postfix.mynetworks", "computed from the host's own interfaces and netmasks"},
	{"smtpd_relay_restrictions", "mail.postfix.smtpd_relay_restrictions",
		"permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination"},
	{"smtpd_recipient_restrictions", "mail.postfix.smtpd_recipient_restrictions", "empty"},
	{"disable_vrfy_command", "mail.postfix.disable_vrfy_command", "no"},
	{"authorized_submit_users", "mail.postfix.authorized_submit_users", "static:anyone"},
}

// goawayExpansion is what sendmail 8.14's goaway flag covers. Ruling L-26:
// which flags it covers is VERSION-dependent, so the literal goaway token is
// kept in the published list alongside this expansion, and only novrfy and
// noexpn — present in every version — are judged.
var goawayExpansion = []string{
	"authwarnings", "noexpn", "novrfy", "noverb",
	"needmailhelo", "needexpnhelo", "needvrfyhelo", "nobodyreturn",
}

// sendmailPrivacyRe matches the sendmail.cf option line this collector
// reads, in both spellings: the long "O PrivacyOptions=" form m4 emits and
// the single-letter "OpPrivacyOptions=" form, with whitespace around the
// separator tolerated either way.
var sendmailPrivacyRe = regexp.MustCompile(`^O(?:\s+|p)PrivacyOptions\s*=(.*)$`)

// mailConfCandidates is every configuration file the collector looks for, in
// probe order — the list a reason names when it found none of them.
func mailConfCandidates() []string {
	var c []string
	for _, im := range mailImpls {
		c = append(c, im.confs...)
	}
	return c
}

// mailParse accumulates what this host's MTA configuration says. impl is the
// implementation the files and binaries agree on; files is every
// configuration file that named or fed the parse.
type mailParse struct {
	a        collect.Access
	impl     string
	mainFile string
	leftover string   // a conffile whose daemon binary is not installed
	also     []string // a SECOND MTA installed beside the one that answers

	files     []string
	truncated []string

	// readFailure is the read that could not answer at all. It is the answer
	// for every value the file could have set (C3).
	readFailure *facts.Envelope

	postfix    map[string]string // lowercased parameter -> raw value, last wins
	privacy    []string          // sendmail's PrivacyOptions flags, expanded and sorted
	privacySet bool              // the .cf carried a PrivacyOptions line at all
}

// runMail publishes the mail keys from configuration files alone: D14 forbids
// invoking the daemon, so nothing here runs postconf(1) and no version is
// derived.
//
// C3: a configuration file that EXISTS but cannot be read is the answer for
// every value it could set — never the daemon's compiled default. A host with
// no MTA at all cannot be said to refuse VRFY, so the judged leaves are
// absent (→ MANUAL) while the evidence leaves stay ok and the run stays
// complete (Ruling L-7).
func runMail(_ context.Context, a collect.Access, b *collect.Builder) error {
	p := &mailParse{a: a, postfix: map[string]string{}}
	p.detect()
	p.publish(b)
	return nil
}

// detect names the implementation this host's files and binaries agree on,
// and reads its configuration. Every modelled MTA is probed, not just the
// first: a host carrying two of them is a real state, and naming the second
// in the implementation's reason is more useful to the operator than a fact
// that quietly describes one of the two.
func (p *mailParse) detect() {
	for _, im := range mailImpls {
		conf, ok := p.present(im)
		if !ok {
			continue
		}
		if p.impl == "" {
			p.impl, p.mainFile = im.name, conf
			continue
		}
		p.also = append(p.also, im.name+" ("+conf+")")
	}
	if p.impl == "" {
		p.impl = "none"
		return
	}
	p.read()
}

// present reports the first configuration file of this MTA that is on disk,
// and whether the package's binary is installed beside it. A conffile with no
// binary is what `apt remove` leaves behind, and judging a removed package's
// file is a confidently wrong verdict either way.
//
// Presence is a stat, not a read: a main.cf that exists but cannot be read
// still names this host a postfix host, and C3 then answers every parameter
// with the read's own failure rather than with "no MTA here".
func (p *mailParse) present(im mailImpl) (string, bool) {
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

// read parses the configuration of the implementation that answers. Only
// that one file is opened: main.cf can NAME other files (a map, a chroot, an
// alias database) and none of them is followed, and the configuration of a
// second MTA installed beside this one is not this host's answer.
func (p *mailParse) read() {
	if p.impl == "exim" {
		// exim's access control lives in ACLs, which this collector does not
		// model, so there is nothing its configuration could tell us that we
		// would be entitled to judge. The file is recorded as the evidence
		// that named the implementation and is never opened.
		p.record(p.mainFile, false)
		return
	}
	data, meta, err := p.a.ReadFile(p.mainFile, readLimit)
	if err != nil {
		e := readErrorEnv(p.mainFile, err)
		p.readFailure = &e
		return
	}
	p.record(p.mainFile, meta.Truncated)
	switch p.impl {
	case "postfix":
		parsePostfixInto(p.postfix, data)
	case "sendmail":
		p.privacy, p.privacySet = parseSendmailPrivacy(data)
	}
}

// record notes a file that reached the parse and whether the read primitive
// cut it at the cap.
func (p *mailParse) record(file string, truncated bool) {
	p.files = append(p.files, file)
	if truncated {
		p.truncated = append(p.truncated, file)
	}
}

// noteLeftover records a configuration file whose daemon binary is not
// installed. The FIRST one found is kept, so the reason is stable.
func (p *mailParse) noteLeftover(conf string, bins []string) {
	if p.leftover == "" {
		p.leftover = conf + " is present but " + strings.Join(bins, " or ") +
			" is not: configuration of a removed package"
	}
}

func (p *mailParse) publish(b *collect.Builder) {
	src := filesSource(p.files)
	cut := len(p.truncated) > 0

	impl := collect.OK(p.impl, p.implSource())
	switch {
	case p.impl == "none" && p.leftover != "":
		// Name the file, so a reader can see it is a leftover to purge rather
		// than a configuration anything was judged by (IR-7).
		impl.Reason = "no mail transfer agent on this host: " + p.leftover
	case len(p.also) > 0:
		impl.Reason = p.impl + " answers these facts; also installed on this host and not read here: " +
			strings.Join(p.also, ", ")
	}
	b.Set("mail.implementation", impl)
	b.Set("mail.config_files", withTruncation(collect.OK(mailList(p.sortedFiles()), src), cut))

	if e := p.judged(); e != nil {
		for _, k := range mailJudgedKeys {
			b.Set(k, *e)
		}
		return
	}
	switch p.impl {
	case "postfix":
		p.publishPostfix(b, src)
	case "sendmail":
		p.publishSendmail(b, src)
	case "exim":
		p.publishExim(b)
	}
}

// judged is the envelope every judged leaf shares when the configuration
// could not be seen, and nil when it could. A read that failed wins over a
// cap: it names a privilege or an I/O problem, which is the more actionable
// of the two.
func (p *mailParse) judged() *facts.Envelope {
	if p.readFailure != nil {
		return p.readFailure
	}
	if len(p.truncated) > 0 {
		e := collect.Absent("the configuration was cut at the read limit in " +
			strings.Join(p.truncated, ", ") + "; what is past the cap cannot be judged")
		return &e
	}
	if p.impl == "none" {
		reason := "no mail transfer agent is installed on this host: none of " +
			strings.Join(mailConfCandidates(), ", ") + " is present with its daemon binary"
		if p.leftover != "" {
			reason = "no mail transfer agent is installed on this host: " + p.leftover
		}
		e := collect.Absent(reason)
		return &e
	}
	return nil
}

func (p *mailParse) publishPostfix(b *collect.Builder, src *facts.Source) {
	for _, pp := range postfixParams {
		b.Set(pp.key, p.postfixValue(pp, src))
	}
	b.Set("mail.sendmail.privacy_options", collect.Absent(
		"the sendmail privacy options are not a postfix setting; this host is configured with postfix"))

	// postfix implements no EXPN command at all — it answers 502 whatever the
	// configuration says — so the one parameter settles both halves of the
	// question, and its own compiled default leaves VRFY answered.
	e := collect.OK(postfixYes(p.postfix["disable_vrfy_command"]), src)
	e.Reason = "postfix implements no EXPN command, so disable_vrfy_command decides both; its compiled default is no"
	b.Set("mail.expn_vrfy_restricted", e)
}

// postfixValue is one parameter as main.cf writes it, with the $name
// references left exactly as they stand: expanding them needs parameters
// this collector does not model, and a half-expanded value would be evidence
// for a configuration no host has.
func (p *mailParse) postfixValue(pp postfixParam, src *facts.Source) facts.Envelope {
	v, ok := p.postfix[pp.param]
	if !ok {
		return collect.Absent(pp.param + " is not set in " + postfixMainCf +
			"; postfix's compiled default is " + pp.def)
	}
	if oversized(v) {
		// The reason names the limit, never the value: the value is exactly
		// what must not be copied into the snapshot (M16).
		return collect.Absent(pp.param + ": " + oversizedReason)
	}
	return collect.OK(v, src)
}

func (p *mailParse) publishSendmail(b *collect.Builder, src *facts.Source) {
	for _, pp := range postfixParams {
		b.Set(pp.key, collect.Absent(pp.param+
			" is not a sendmail setting; this host is configured with sendmail"))
	}
	opts := collect.OK(mailList(p.privacy), src)
	if !p.privacySet {
		// An empty list is the honest answer: the file was READ and it sets
		// no privacy flags. That is a different finding from an absence.
		opts.Reason = sendmailCf + " carries no PrivacyOptions line; sendmail's compiled default is public, " +
			"which answers both VRFY and EXPN"
	}
	b.Set("mail.sendmail.privacy_options", opts)

	e := collect.OK(slices.Contains(p.privacy, "novrfy") && slices.Contains(p.privacy, "noexpn"), src)
	e.Reason = "novrfy and noexpn are the two privacy flags every sendmail version carries; " +
		"a goaway is expanded before this test"
	b.Set("mail.expn_vrfy_restricted", e)
}

func (p *mailParse) publishExim(b *collect.Builder) {
	reason := "this host is configured with exim, whose configuration this collector does not parse"
	for _, pp := range postfixParams {
		b.Set(pp.key, collect.Absent(reason))
	}
	b.Set("mail.sendmail.privacy_options", collect.Absent(reason))
	b.Set("mail.expn_vrfy_restricted", collect.Absent(
		"exim decides VRFY and EXPN in its ACLs, which this collector does not model"))
}

func (p *mailParse) implSource() *facts.Source {
	if p.mainFile != "" {
		return &facts.Source{Kind: "file", Path: p.mainFile}
	}
	return &facts.Source{Kind: "derived"}
}

func (p *mailParse) sortedFiles() []string {
	files := append([]string(nil), p.files...)
	slices.Sort(files)
	return files
}

// mailList renders a string slice as the []any a list-valued fact carries,
// empty rather than nil so it serialises as "[]" (R50).
func mailList(items []string) []any {
	out := []any{}
	for _, s := range items {
		out = append(out, s)
	}
	return out
}

// parsePostfixInto folds one main.cf into the parameter map.
//
// postconf(5)'s grammar: a logical line is "parameter = value"; an empty
// line, a whitespace-only line and a line whose first non-whitespace
// character is '#' are ignored; a line that STARTS with whitespace continues
// the logical line above it. A '#' anywhere else belongs to the value —
// postfix strips no trailing comment, and a value cut at one would be a
// different setting. A later assignment of the same parameter wins, which is
// what postfix itself does. Parameter names are folded to lower case (they
// are lower case in practice, and a control must not have to match two
// spellings); the value keeps its own case, because it is evidence.
func parsePostfixInto(dst map[string]string, data []byte) {
	last := ""
	for _, raw := range splitLines(data) {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if raw[0] == ' ' || raw[0] == '\t' {
			if last == "" {
				continue
			}
			dst[last] = strings.TrimSpace(dst[last] + " " + trimmed)
			continue
		}
		k, v, ok := strings.Cut(raw, "=")
		if !ok {
			// Not an assignment at all. postfix refuses to start on it; there
			// is nothing here to attribute, and the next indented line has no
			// parameter left to extend.
			last = ""
			continue
		}
		last = strings.ToLower(strings.TrimSpace(k))
		dst[last] = strings.TrimSpace(v)
	}
}

// postfixYes reads postfix's boolean form. postfix accepts yes/no,
// true/false, on/off and 1/0, case-insensitively; anything else makes it
// refuse to start, so the compiled default — false for every boolean this
// collector reads — is the honest answer for it too.
func postfixYes(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "true", "on", "1":
		return true
	}
	return false
}

// parseSendmailPrivacy is the PrivacyOptions list of a sendmail.cf, and
// whether the file carried such a line at all. The FIRST matching line is
// the answer, so the same file always yields the same list.
func parseSendmailPrivacy(data []byte) ([]string, bool) {
	for _, raw := range splitLines(data) {
		m := sendmailPrivacyRe.FindStringSubmatch(raw)
		if m == nil {
			continue
		}
		return expandPrivacyOptions(strings.Split(m[1], ",")), true
	}
	return nil, false
}

// expandPrivacyOptions folds one comma-separated PrivacyOptions list into the
// sorted, deduplicated set of flags it means. Ruling L-26: goaway is KEPT as
// written and its 8.14 expansion appended, because which flags it covers
// changes between releases — the literal token is the evidence, and only
// novrfy and noexpn, present in every version, are judged.
func expandPrivacyOptions(tokens []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(t string) {
		if t == "" || seen[t] {
			return
		}
		seen[t] = true
		out = append(out, t)
	}
	for _, t := range tokens {
		t = strings.ToLower(strings.TrimSpace(t))
		add(t)
		if t == "goaway" {
			for _, e := range goawayExpansion {
				add(e)
			}
		}
	}
	slices.Sort(out)
	return out
}
