package collectors

import (
	"sort"
	"strconv"
	"strings"
)

// The sudoers rules (P-2). This file has no build tag: it reads bytes,
// touches nothing, and is tested on every platform. The files collector's
// sudo reader (files_sudo.go) walks the chain of files and hands each one
// to parseSudoers beside parseSudoersDefaults, which keeps serving sudo.log.*.
//
// The grammar is sudoers(5)'s: a user specification is
//
//	User_List Host_List = Cmnd_Spec_List [: Host_List = Cmnd_Spec_List]…
//
// where a Runas_Spec "(…)" and a tag "NOPASSWD:" apply to the command they
// precede and to every later command of the same Cmnd_Spec_List until
// another of the same kind, and ":" starts a privilege afresh.

const (
	// sudoAliasDepth bounds alias substitution: an alias reached through
	// more than eight others is not resolved.
	sudoAliasDepth = 8
	// sudoRuleCap bounds the published sudo.rules list (V-12).
	sudoRuleCap = 2000
	// sudoExpandBudget bounds the alias members one resolveRules call emits
	// and sudoRowBudget the commands its rows carry (one at least per row);
	// past either, what is left is unresolved rather than read, so the
	// answers turn absent, never wrong.
	sudoExpandBudget = 1 << 16
	sudoRowBudget    = 1 << 16

	sudoIncludeDir = "includedir"
	sudoInclude    = "include"
)

// sudoRule is one row of sudo.rules: one principal, one privilege, one run
// of commands sharing a Runas_Spec.
type sudoRule struct {
	File      string
	Line      int
	Principal string
	Kind      string // user | group | uid | gid | all | alias | netgroup | nonunix
	Negated   bool
	Runas     string // the Runas_Spec's text with aliases substituted; "" when none
	NoPasswd  bool   // some command of the row carries NOPASSWD
	Commands  []string
	Resolved  bool

	// allNoPasswd is whether the ALL command itself, not negated, carries
	// NOPASSWD — the narrower question sudo.nopasswd_all asks.
	allNoPasswd bool
	// unresolvedBy names what could not be resolved: an alias, a netgroup,
	// a non-Unix group, or file:line for a specification that did not parse.
	unresolvedBy []string
}

// sudoersFile is what one sudoers file (or one stretch of it between
// include directives, see sudoSegments) contributes.
type sudoersFile struct {
	Path     string
	Aliases  map[string]map[string][]string // User_Alias|Runas_Alias|Cmnd_Alias|Host_Alias → name → members ("!" kept)
	Specs    []sudoSpec
	Defaults []sudoDefault
	Includes []int // the lines of the include directives, in order
}

// sudoSpec is one user specification. Privileges is nil when the line has
// an "=" but does not parse; its principals are then unresolved.
type sudoSpec struct {
	Line       int
	Users      []string // raw principal tokens, "!" kept for an odd count
	Privileges []sudoPrivilege
}

type sudoPrivilege struct {
	Hosts    []string
	Commands []sudoCommand
}

type sudoCommand struct {
	Runas, Text string
	NoPasswd    bool
}

// sudoDefault is one Defaults line: Scope 0 unscoped, or ':', '>', '@', '!'
// with the list it is scoped to in Target.
type sudoDefault struct {
	Line    int
	Scope   byte
	Target  string
	Options []sudoOption
}

// sudoOption is one Defaults option: its name, whether it was negated with
// "!", and its value with quotes removed ("" when it has none).
type sudoOption struct {
	name    string
	negated bool
	value   string
}

var sudoTags = map[string]bool{
	"NOPASSWD": true, "PASSWD": true, "NOEXEC": true, "EXEC": true, "SETENV": true, "NOSETENV": true,
	"LOG_INPUT": true, "NOLOG_INPUT": true, "LOG_OUTPUT": true, "NOLOG_OUTPUT": true,
	"MAIL": true, "NOMAIL": true, "FOLLOW": true, "NOFOLLOW": true, "INTERCEPT": true, "NOINTERCEPT": true,
}

// sudoCmndOptions are the Option_Spec words of a Cmnd_Spec (NAME=value).
var sudoCmndOptions = map[string]bool{
	"ROLE": true, "TYPE": true, "PRIVS": true, "LIMITPRIVS": true, "NOTBEFORE": true, "NOTAFTER": true,
	"TIMEOUT": true, "CWD": true, "CHROOT": true,
}

var sudoDigests = map[string]bool{"sha224": true, "sha256": true, "sha384": true, "sha512": true}

// sudoDigestWord is an algorithm and its digest as the lexer joins them.
func sudoDigestWord(s string) bool {
	alg, _, ok := strings.Cut(s, ":")
	return ok && sudoDigests[alg]
}

// sudoDigestByte is a character of a hex or base64 digest, padding included.
func sudoDigestByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '+' || c == '/' || c == '='
}

var sudoAliasTypes = map[string]string{
	"User_Alias": "User_Alias", "Runas_Alias": "Runas_Alias", "Host_Alias": "Host_Alias",
	"Cmnd_Alias": "Cmnd_Alias", "Cmd_Alias": "Cmnd_Alias",
}

// sudoLogicalLine is a line with its "\" continuations joined, and the
// number of the physical line it starts on.
type sudoLogicalLine struct {
	n    int
	text string
}

// sudoLogicalLines classifies, then joins (V-42, V-43): a line that starts a
// comment ends at its newline, a trailing "\" notwithstanding, as sudo's
// lexer ends it; every other line — a "#1000" uid line included — is joined
// with the next while it ends in "\", until a comment line closes it.
func sudoLogicalLines(data []byte) []sudoLogicalLine {
	var out []sudoLogicalLine
	var cur strings.Builder
	start, joining := 0, false
	for i, raw := range strings.Split(string(data), "\n") {
		t := strings.TrimRight(strings.TrimSuffix(raw, "\r"), " \t")
		if sudoCommentLine(strings.TrimSpace(t)) {
			// V-43: a comment reached while joining closes the logical
			// line — sudo reads the "\"-newline as a blank, then the
			// comment to its newline — and is dropped.
			if joining {
				out = append(out, sudoLogicalLine{n: start, text: strings.TrimSpace(cur.String())})
				cur.Reset()
				joining = false
			}
			continue
		}
		if !joining {
			start = i + 1
		}
		if strings.HasSuffix(t, `\`) {
			cur.WriteString(strings.TrimSuffix(t, `\`))
			cur.WriteByte(' ')
			joining = true
			continue
		}
		cur.WriteString(t)
		out = append(out, sudoLogicalLine{n: start, text: strings.TrimSpace(cur.String())})
		cur.Reset()
		joining = false
	}
	if joining {
		out = append(out, sudoLogicalLine{n: start, text: strings.TrimSpace(cur.String())})
	}
	return out
}

// sudoCommentLine is a line whose first token is a comment: a "#" that is
// neither an include directive nor the start of a uid (#1000, #-1).
func sudoCommentLine(s string) bool {
	if !strings.HasPrefix(s, "#") {
		return false
	}
	if _, _, ok := sudoDirective(s); ok {
		return false
	}
	return !sudoUIDStart(s[1:])
}

// sudoUIDStart is whether what follows a "#" makes it a uid: a digit, or
// "-" and a digit.
func sudoUIDStart(s string) bool {
	s = strings.TrimPrefix(s, "-")
	return s != "" && s[0] >= '0' && s[0] <= '9'
}

// parseSudoers reads one sudoers file for its aliases, user specifications,
// Defaults lines (all five scopes) and the lines of its include directives.
// "#include"/"#includedir" are directives; a "#" followed by a digit starts
// a uid token, as sudo reads it, so "#1 first rule" with an "=" is a rule
// that does not parse and without one is dropped; every other "#" outside
// quotes starts a comment.
func parseSudoers(data []byte, p string) sudoersFile {
	f := sudoersFile{Path: p, Aliases: map[string]map[string][]string{}}
	for _, l := range sudoLogicalLines(data) {
		text := l.text
		if text == "" {
			continue
		}
		if _, _, ok := sudoDirective(text); ok {
			f.Includes = append(f.Includes, l.n)
			continue
		}
		if rest, ok := strings.CutPrefix(text, "Defaults"); ok && rest != "" {
			switch c := rest[0]; {
			case c == ':' || c == '>' || c == '@' || c == '!':
				target, opts := rest[1:], ""
				if i := strings.IndexAny(target, " \t"); i >= 0 {
					target, opts = target[:i], target[i:]
				}
				f.Defaults = append(f.Defaults, sudoDefault{Line: l.n, Scope: c, Target: target, Options: sudoOptions(opts)})
				continue
			case c == ' ' || c == '\t':
				f.Defaults = append(f.Defaults, sudoDefault{Line: l.n, Options: sudoOptions(rest)})
				continue
			}
		}
		word, rest, _ := strings.Cut(strings.ReplaceAll(text, "\t", " "), " ")
		if typ, ok := sudoAliasTypes[word]; ok {
			f.addAliases(typ, sudoLex(rest))
			continue
		}
		toks := sudoLex(text)
		if !sudoHasEquals(toks) {
			continue
		}
		f.Specs = append(f.Specs, parseSudoSpec(toks, l.n))
	}
	return f
}

// sudoTok is a token of a user specification or alias line: a word ('w'),
// or one of the separators , = : ( ) and the negation !.
type sudoTok struct {
	kind byte
	text string
}

// sudoLex splits a logical line into tokens. A backslash escapes the next
// character, double quotes group (the quotes are removed), blanks end a
// word, and a comment ends the line.
func sudoLex(s string) []sudoTok {
	var toks []sudoTok
	var w strings.Builder
	inWord := false
	flush := func() {
		if inWord {
			toks = append(toks, sudoTok{'w', w.String()})
			w.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			i++
			w.WriteByte(s[i])
			inWord = true
		case c == '"':
			j := strings.IndexByte(s[i+1:], '"')
			if j < 0 {
				j = len(s) - i - 1
			}
			q := s[i+1 : i+1+j]
			if q == "" && !inWord {
				q = `""`
			}
			w.WriteString(q)
			inWord = true
			i += j + 1
		case c == ' ' || c == '\t':
			flush()
		case c == '#' && !inWord:
			if sudoUIDStart(s[i+1:]) {
				w.WriteByte(c)
				inWord = true
				continue
			}
			flush()
			return toks
		case c == '!' && !inWord:
			toks = append(toks, sudoTok{'!', "!"})
		case c == ':' && inWord && w.String() == "%":
			w.WriteByte(c) // %:nonunix_group
		case c == ':' && inWord && sudoDigests[w.String()]:
			// A Digest_Spec: the hex or base64 digest, "=" padding
			// included, is one word with its algorithm (sha224:0Gom…==).
			w.WriteByte(c)
			for i+1 < len(s) && (s[i+1] == ' ' || s[i+1] == '\t') {
				i++
			}
			for i+1 < len(s) && sudoDigestByte(s[i+1]) {
				i++
				w.WriteByte(s[i])
			}
		case c == ',' || c == '=' || c == ':' || c == '(' || c == ')':
			flush()
			toks = append(toks, sudoTok{c, string(c)})
		default:
			w.WriteByte(c)
			inWord = true
		}
	}
	flush()
	return toks
}

func sudoHasEquals(toks []sudoTok) bool {
	for _, t := range toks {
		if t.kind == '=' {
			return true
		}
	}
	return false
}

// sudoParser walks a token list.
type sudoParser struct {
	toks []sudoTok
	i    int
}

func (p *sudoParser) peek(k int) sudoTok {
	if p.i+k < len(p.toks) {
		return p.toks[p.i+k]
	}
	return sudoTok{}
}

func (p *sudoParser) is(kind byte) bool { return p.peek(0).kind == kind }

func (p *sudoParser) done() bool { return p.i >= len(p.toks) }

// bangs consumes "!" operators and says whether their count is odd.
func (p *sudoParser) bangs() bool {
	neg := false
	for p.is('!') {
		neg = !neg
		p.i++
	}
	return neg
}

// item reads one list member — "!"* word — spelled with one "!" when it is
// negated.
func (p *sudoParser) item() (string, bool) {
	neg := p.bangs()
	if !p.is('w') {
		return "", false
	}
	w := p.peek(0).text
	p.i++
	if neg {
		w = "!" + w
	}
	return w, true
}

// list reads item ("," item)*.
func (p *sudoParser) list() ([]string, bool) {
	var out []string
	for {
		w, ok := p.item()
		if !ok {
			return out, false
		}
		out = append(out, w)
		if !p.is(',') {
			return out, true
		}
		p.i++
	}
}

// cmnd reads Digest_List? "!"* command, the command's words joined by one
// blank; a digest list stays in front of the command it pins
// (sha256:ab…,sha512:cd… /bin/ls).
func (p *sudoParser) cmnd() (string, bool) {
	neg := p.bangs()
	var digests []string
	for p.is('w') && sudoDigestWord(p.peek(0).text) {
		digests = append(digests, p.peek(0).text)
		p.i++
		if p.is(',') && p.peek(1).kind == 'w' && sudoDigestWord(p.peek(1).text) {
			p.i++
			continue
		}
		if p.bangs() {
			neg = !neg
		}
		break
	}
	var words []string
	if len(digests) > 0 {
		words = append(words, strings.Join(digests, ","))
	}
	lead := len(words)
	for p.is('w') {
		words = append(words, p.peek(0).text)
		p.i++
	}
	if len(words) == lead {
		return "", false
	}
	text := strings.Join(words, " ")
	if neg {
		text = "!" + text
	}
	return text, true
}

// runas reads "(" users [":" groups] ")" after the "(" and renders it
// without blanks: (ALL:ALL), (root), (:adm).
func (p *sudoParser) runas() (string, bool) {
	var users, groups []string
	var ok bool
	if !p.is(':') && !p.is(')') {
		if users, ok = p.list(); !ok {
			return "", false
		}
	}
	colon := false
	if p.is(':') {
		colon = true
		p.i++
		if !p.is(')') {
			if groups, ok = p.list(); !ok {
				return "", false
			}
		}
	}
	if !p.is(')') {
		return "", false
	}
	p.i++
	return sudoRunasText(users, groups, colon), true
}

func sudoRunasText(users, groups []string, colon bool) string {
	s := "(" + strings.Join(users, ",")
	if colon {
		s += ":" + strings.Join(groups, ",")
	}
	return s + ")"
}

// cmndSpecList reads Cmnd_Spec ("," Cmnd_Spec)*, carrying the Runas_Spec
// and the PASSWD/NOPASSWD tag from one command to the next.
func (p *sudoParser) cmndSpecList() ([]sudoCommand, bool) {
	var out []sudoCommand
	runas, nopasswd := "", false
	for {
		if p.is('(') {
			p.i++
			r, ok := p.runas()
			if !ok {
				return out, false
			}
			runas = r
		}
		for p.is('w') && sudoCmndOptions[p.peek(0).text] && p.peek(1).kind == '=' {
			p.i += 2
			if p.is('w') {
				p.i++
			}
		}
		for p.is('w') && sudoTags[p.peek(0).text] && p.peek(1).kind == ':' {
			switch p.peek(0).text {
			case "NOPASSWD":
				nopasswd = true
			case "PASSWD":
				nopasswd = false
			}
			p.i += 2
		}
		text, ok := p.cmnd()
		if !ok {
			return out, false
		}
		out = append(out, sudoCommand{Runas: runas, Text: text, NoPasswd: nopasswd})
		if !p.is(',') {
			return out, true
		}
		p.i++
	}
}

// parseSudoSpec reads a user specification; a line that does not parse
// keeps the principals it named and no privilege.
func parseSudoSpec(toks []sudoTok, n int) sudoSpec {
	p := &sudoParser{toks: toks}
	users, ok := p.list()
	spec := sudoSpec{Line: n, Users: users}
	if !ok || len(users) == 0 {
		if len(spec.Users) == 0 {
			spec.Users = []string{""}
		}
		return spec
	}
	var privs []sudoPrivilege
	for {
		hosts, ok := p.list()
		if !ok || !p.is('=') {
			return spec
		}
		p.i++
		cmds, ok := p.cmndSpecList()
		if !ok {
			return spec
		}
		privs = append(privs, sudoPrivilege{Hosts: hosts, Commands: cmds})
		if p.done() {
			break
		}
		if !p.is(':') {
			return spec
		}
		p.i++
	}
	spec.Privileges = privs
	return spec
}

// addAliases reads NAME = list [: NAME = list]… after the alias keyword. A
// name defined twice keeps its first definition (sudo refuses the file).
func (f *sudoersFile) addAliases(typ string, toks []sudoTok) {
	p := &sudoParser{toks: toks}
	for p.is('w') && p.peek(1).kind == '=' {
		name := p.peek(0).text
		p.i += 2
		var members []string
		for {
			var w string
			var ok bool
			if typ == "Cmnd_Alias" {
				w, ok = p.cmnd()
			} else {
				w, ok = p.item()
			}
			if !ok {
				break
			}
			members = append(members, w)
			if !p.is(',') {
				break
			}
			p.i++
		}
		if sudoAliasName(name) {
			if f.Aliases[typ] == nil {
				f.Aliases[typ] = map[string][]string{}
			}
			if _, dup := f.Aliases[typ][name]; !dup {
				f.Aliases[typ][name] = members
			}
		}
		if !p.is(':') {
			return
		}
		p.i++
	}
}

// sudoAliasName is sudoers' NAME: an uppercase letter, then uppercase
// letters, digits and underscores. ALL is reserved, never an alias.
func sudoAliasName(s string) bool {
	if s == "" || s == "ALL" || s[0] < 'A' || s[0] > 'Z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// sudoPrincipalKind names a principal's kind from its spelling.
func sudoPrincipalKind(s string) string {
	switch {
	case s == "ALL":
		return "all"
	case strings.HasPrefix(s, "%:"):
		return "nonunix"
	case strings.HasPrefix(s, "%#"):
		return "gid"
	case strings.HasPrefix(s, "%"):
		return "group"
	case strings.HasPrefix(s, "#"):
		return "uid"
	case strings.HasPrefix(s, "+"):
		return "netgroup"
	case sudoAliasName(s):
		return "alias"
	}
	return "user"
}

// sudoNegation strips the "!" a stored token carries for an odd count.
func sudoNegation(s string) (string, bool) {
	if rest, ok := strings.CutPrefix(s, "!"); ok {
		return rest, true
	}
	return s, false
}

type sudoResolver struct {
	aliases map[string]map[string][]string
	steps   int // alias members emitted so far, bounded by sudoExpandBudget
}

// charge counts the members an alias expansion is about to emit and says
// whether they would pass the budget: that alias is then left unresolved
// rather than expanded (its one unresolved marker stands for a member
// already charged), so aliases that multiply each other emit at most twice
// sudoExpandBudget members over one resolveRules call.
func (r *sudoResolver) charge(n int) bool {
	if r.steps+n > sudoExpandBudget {
		return true
	}
	r.steps += n
	return false
}

type sudoPrincipal struct {
	name, kind string
	neg, ok    bool
	why        string
}

func (r *sudoResolver) members(typ, name string) ([]string, bool) {
	m, ok := r.aliases[typ][name]
	return m, ok
}

// principals expands one User_List token; a negated alias negates every
// member.
func (r *sudoResolver) principals(tok string, neg bool, depth int, visiting map[string]bool) []sudoPrincipal {
	name, n := sudoNegation(tok)
	neg = neg != n
	kind := sudoPrincipalKind(name)
	switch kind {
	case "alias":
		members, defined := r.members("User_Alias", name)
		if !defined || visiting[name] || depth >= sudoAliasDepth || r.charge(len(members)) {
			return []sudoPrincipal{{name: name, kind: kind, neg: neg, why: name}}
		}
		visiting[name] = true
		var out []sudoPrincipal
		for _, m := range members {
			out = append(out, r.principals(m, neg, depth+1, visiting)...)
		}
		delete(visiting, name)
		return out
	case "netgroup", "nonunix":
		return []sudoPrincipal{{name: name, kind: kind, neg: neg, why: name}}
	}
	return []sudoPrincipal{{name: name, kind: kind, neg: neg, ok: true}}
}

type sudoResolvedCmd struct {
	text string
	neg  bool
	ok   bool
	why  string
}

// commands expands one command text through Cmnd_Alias.
func (r *sudoResolver) commands(text string, neg bool, depth int, visiting map[string]bool) []sudoResolvedCmd {
	name, n := sudoNegation(text)
	neg = neg != n
	if !sudoAliasName(name) {
		return []sudoResolvedCmd{{text: name, neg: neg, ok: true}}
	}
	members, defined := r.members("Cmnd_Alias", name)
	if !defined || visiting[name] || depth >= sudoAliasDepth || r.charge(len(members)) {
		return []sudoResolvedCmd{{text: name, neg: neg, why: name}}
	}
	visiting[name] = true
	var out []sudoResolvedCmd
	for _, m := range members {
		out = append(out, r.commands(m, neg, depth+1, visiting)...)
	}
	delete(visiting, name)
	return out
}

// runasMembers expands one Runas_List member through Runas_Alias.
func (r *sudoResolver) runasMembers(tok string, neg bool, depth int, visiting map[string]bool, why *[]string) []string {
	name, n := sudoNegation(tok)
	neg = neg != n
	if !sudoAliasName(name) {
		if neg {
			name = "!" + name
		}
		return []string{name}
	}
	members, defined := r.members("Runas_Alias", name)
	if !defined || visiting[name] || depth >= sudoAliasDepth || r.charge(len(members)) {
		*why = append(*why, name)
		if neg {
			name = "!" + name
		}
		return []string{name}
	}
	visiting[name] = true
	var out []string
	for _, m := range members {
		out = append(out, r.runasMembers(m, neg, depth+1, visiting, why)...)
	}
	delete(visiting, name)
	return out
}

// runas substitutes the Runas_Alias members of a rendered Runas_Spec.
func (r *sudoResolver) runas(text string) (string, []string) {
	inner, ok := strings.CutPrefix(text, "(")
	if !ok {
		return text, nil
	}
	inner = strings.TrimSuffix(inner, ")")
	userPart, groupPart, colon := strings.Cut(inner, ":")
	var why []string
	expand := func(part string) []string {
		var out []string
		if part == "" {
			return nil
		}
		for _, m := range strings.Split(part, ",") {
			out = append(out, r.runasMembers(m, false, 0, map[string]bool{}, &why)...)
		}
		return out
	}
	users, groups := expand(userPart), expand(groupPart)
	return sudoRunasText(users, groups, colon), why
}

// sudoRun is the commands of one privilege that share a Runas_Spec.
type sudoRun struct {
	runas       string
	commands    []string
	nopasswd    bool
	allNoPasswd bool
	why         []string
}

func (r *sudoResolver) runs(priv sudoPrivilege) []sudoRun {
	var out []sudoRun
	for i, c := range priv.Commands {
		if i == 0 || c.Runas != priv.Commands[i-1].Runas {
			text, why := r.runas(c.Runas)
			out = append(out, sudoRun{runas: text, commands: []string{}, why: why})
		}
		run := &out[len(out)-1]
		for _, rc := range r.commands(c.Text, false, 0, map[string]bool{}) {
			t := rc.text
			if rc.neg {
				t = "!" + t
			}
			run.commands = append(run.commands, t)
			run.nopasswd = run.nopasswd || c.NoPasswd
			if rc.text == "ALL" && !rc.neg && rc.ok && c.NoPasswd {
				run.allNoPasswd = true
			}
			if !rc.ok {
				run.why = append(run.why, rc.why)
			}
		}
	}
	return out
}

// resolveRules turns the files' specifications into rows, one per
// principal per privilege per run of a Runas_Spec, substituting aliases to
// a depth of eight. A cycle, an undefined alias, a netgroup, a non-Unix
// group or a specification that did not parse leaves the row unresolved.
// Aliases are global across the files, the first definition winning, and
// are merged before any rule is resolved: sudo resolves an alias when it
// matches, after reading every file, so a definition after its use (later
// in the file or in a later drop-in) counts. Hosts are not judged: every
// specification counts as if its Host_List matched this host.
func resolveRules(files []sudoersFile) (rules []sudoRule, unresolved int) {
	r := &sudoResolver{aliases: map[string]map[string][]string{}}
	for _, f := range files {
		for typ, names := range f.Aliases {
			if r.aliases[typ] == nil {
				r.aliases[typ] = map[string][]string{}
			}
			for name, members := range names {
				if _, dup := r.aliases[typ][name]; !dup {
					r.aliases[typ][name] = members
				}
			}
		}
	}
	rules = []sudoRule{}
	spent := 0 // commands (one at least per row) the rows carry, bounded by sudoRowBudget
	for _, f := range files {
		for _, spec := range f.Specs {
			var runs []sudoRun
			for _, priv := range spec.Privileges {
				runs = append(runs, r.runs(priv)...)
			}
			if spec.Privileges == nil {
				runs = []sudoRun{{commands: []string{}, why: []string{f.Path + ":" + strconv.Itoa(spec.Line)}}}
			}
			// A principal an alias names twice is one principal.
			var principals []sudoPrincipal
			seen := map[sudoPrincipal]bool{}
			for _, u := range spec.Users {
				for _, pr := range r.principals(u, false, 0, map[string]bool{}) {
					if !seen[pr] {
						seen[pr] = true
						principals = append(principals, pr)
					}
				}
			}
			for _, pr := range principals {
				for _, run := range runs {
					rule := sudoRule{
						File: f.Path, Line: spec.Line, Principal: pr.name, Kind: pr.kind, Negated: pr.neg,
						Runas: run.runas, NoPasswd: run.nopasswd, Commands: run.commands,
						allNoPasswd: run.allNoPasswd,
					}
					if !pr.ok {
						rule.unresolvedBy = append(rule.unresolvedBy, pr.why)
					}
					rule.unresolvedBy = append(rule.unresolvedBy, run.why...)
					// A row costs its commands (one at least): every row of
					// a specification shares one command list, but the row
					// that publishes it copies it, so the budget counts what
					// the rows carry, not how many there are (V-65).
					cost := max(1, len(run.commands))
					past := spent+cost > sudoRowBudget
					if past {
						// The rows past the budget are not read: the last row
						// says so, and the answers that need them are absent.
						rule.unresolvedBy = []string{"the rules past the first " + strconv.Itoa(sudoRowBudget) + " commands"}
					}
					spent += cost
					rule.Resolved = len(rule.unresolvedBy) == 0
					if !rule.Resolved {
						unresolved++
					}
					rules = append(rules, rule)
					if past {
						return rules, unresolved
					}
				}
			}
		}
	}
	return rules, unresolved
}

// sudoRuleRows is the published sudo.rules list: the first sudoRuleCap
// rules, cut before any row is built so nothing past the cap is copied
// (V-65), and whether the list was cut.
func sudoRuleRows(rules []sudoRule) ([]any, bool) {
	shown := rules[:min(len(rules), sudoRuleCap)]
	rows := make([]any, 0, len(shown))
	for _, r := range shown {
		cmds := make([]any, 0, len(r.Commands))
		for _, c := range r.Commands {
			cmds = append(cmds, c)
		}
		rows = append(rows, map[string]any{
			"file": r.File, "line": r.Line, "principal": r.Principal, "kind": r.Kind, "negated": r.Negated,
			"runas": r.Runas, "nopasswd": r.NoPasswd, "commands": cmds, "resolved": r.Resolved,
		})
	}
	return rows, len(rules) > len(shown)
}

// unresolvedNames is what the unresolved rules need, sorted and unique.
func unresolvedNames(rules []sudoRule) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, r := range rules {
		for _, w := range r.unresolvedBy {
			if !seen[w] {
				seen[w] = true
				out = append(out, w)
			}
		}
	}
	sort.Strings(out)
	return out
}

// nopasswdAll is the principals other than root and #0 — ALL included —
// that receive the ALL command itself under NOPASSWD, whatever the runas and
// whatever else the list negates. Negated and unresolved rows grant
// nothing here. Sorted, unique.
func nopasswdAll(rules []sudoRule) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, r := range rules {
		if !r.Resolved || r.Negated || !r.allNoPasswd || r.Principal == "root" || r.Principal == "#0" || seen[r.Principal] {
			continue
		}
		seen[r.Principal] = true
		out = append(out, r.Principal)
	}
	sort.Strings(out)
	return out
}

// authenticateDisabled applies the Defaults lines in order, a later line
// winning for the same scope and target, and says whether !authenticate is
// in force for the unscoped Defaults or for any Defaults:User_List or
// Defaults>Runas_List. Defaults@host and Defaults!command are parked (§1).
func authenticateDisabled(files []sudoersFile) bool {
	state := map[string]bool{}
	var order []string
	for _, f := range files {
		for _, d := range f.Defaults {
			if d.Scope != 0 && d.Scope != ':' && d.Scope != '>' {
				continue
			}
			key := string(rune(d.Scope)) + d.Target
			for _, o := range d.Options {
				if o.name != "authenticate" {
					continue
				}
				if _, ok := state[key]; !ok {
					order = append(order, key)
				}
				state[key] = o.negated
			}
		}
	}
	for _, k := range order {
		if state[k] {
			return true
		}
	}
	return false
}

// sudoSegments splits a parsed file at its include directives, so the
// Defaults after a directive are applied after the files it includes, as
// sudo applies them. The first segment carries the aliases and the
// specifications (whose order does not matter); every segment carries the
// Defaults between two directives.
func sudoSegments(f sudoersFile) []sudoersFile {
	segs := make([]sudoersFile, len(f.Includes)+1)
	for i := range segs {
		segs[i].Path = f.Path
	}
	segs[0].Aliases, segs[0].Specs, segs[0].Includes = f.Aliases, f.Specs, f.Includes
	for _, d := range f.Defaults {
		j := sort.SearchInts(f.Includes, d.Line)
		segs[j].Defaults = append(segs[j].Defaults, d)
	}
	return segs
}

// sudoDirective recognises @include, @includedir and their # spellings.
func sudoDirective(s string) (kind, arg string, ok bool) {
	f := strings.Fields(s)
	if len(f) < 2 {
		return "", "", false
	}
	switch f[0] {
	case "@includedir", "#includedir":
		return sudoIncludeDir, strings.Trim(f[1], `"`), true
	case "@include", "#include":
		return sudoInclude, strings.Trim(f[1], `"`), true
	}
	return "", "", false
}

// sudoOptions splits a Defaults option list on the commas outside double
// quotes, stops at an unquoted comment, and reads each option.
func sudoOptions(s string) []sudoOption {
	var parts []string
	var b strings.Builder
	quoted, escaped := false, false
scan:
	for _, r := range s {
		switch {
		case escaped:
			escaped = false
		case r == '\\':
			escaped = true
		case r == '"':
			quoted = !quoted
		case r == ',' && !quoted:
			parts = append(parts, b.String())
			b.Reset()
			continue
		case r == '#' && !quoted:
			break scan
		}
		b.WriteRune(r)
	}
	parts = append(parts, b.String())
	var out []sudoOption
	for _, p := range parts {
		p = strings.TrimSpace(p)
		neg := false
		for strings.HasPrefix(p, "!") {
			neg = !neg
			p = strings.TrimSpace(p[1:])
		}
		name, rest := p, ""
		if end := strings.IndexAny(p, "=+- \t"); end >= 0 {
			name, rest = p[:end], strings.TrimSpace(p[end:])
		}
		if name == "" {
			continue
		}
		value := ""
		for _, op := range []string{"+=", "-=", "="} {
			if v, ok := strings.CutPrefix(rest, op); ok {
				value = strings.TrimSpace(v)
				break
			}
		}
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		out = append(out, sudoOption{name: name, negated: neg, value: value})
	}
	return out
}
