package anonymize

import (
	"encoding/json"
	"fmt"
	"strings"
)

// scalar rewrites one scalar by its rule. A JSON null stays null and a
// number or a boolean is kept in every class but blank; every class maps ""
// to itself (AX-4).
func (w *walker) scalar(r FieldRule, dp string, v any) any {
	if w.err != nil {
		return nil
	}
	switch r.Class {
	case ClassKept:
		return v
	case ClassBlank:
		return w.blank(dp, v)
	case "":
		if v != nil {
			w.fail(dp) // a structural row holding a scalar
		}
		return v
	}
	s, ok := v.(string)
	if !ok {
		return v
	}
	if w.collect {
		switch r.Class {
		case ClassAccount, ClassHostOrAddr, ClassHostOrNetgroup, ClassURL, ClassGrammar:
		default:
			return s
		}
	}
	return w.text(r.Class, r.Grammar, dp, s)
}

func (w *walker) text(c Class, g *Grammar, dp, s string) string {
	switch c {
	case ClassKept:
		return s
	case ClassPlaceholder:
		return w.placeholder(dp, s)
	case ClassBlank:
		return w.blank(dp, s).(string)
	case ClassAccount:
		return w.account(dp, s)
	case ClassHost:
		return w.host(dp, s)
	case ClassAddress:
		return w.address(dp, s)
	case ClassHostOrAddr:
		return w.hostOrAddr(dp, s, false)
	case ClassHostOrNetgroup:
		return w.hostOrAddr(dp, s, true)
	case ClassURL:
		return w.url(dp, s)
	case ClassFingerprint:
		return w.mapped(dp, ClassFingerprint, s, w.k.Fingerprint)
	case ClassMachineID:
		return w.mapped(dp, ClassMachineID, s, w.k.MachineIDHash)
	case ClassPath:
		return w.path(dp, s)
	case ClassGrammar:
		return w.grammar(dp, g, s)
	}
	if w.err == nil {
		w.err = fmt.Errorf("anonymization table: unknown class %q at %s", c, dp)
	}
	return s
}

func (w *walker) note(dp, class, in, out string) {
	if w.collect || w.err != nil {
		return
	}
	if err := w.ledger.Note(dp, class, in, out); err != nil {
		w.err = err
		return
	}
	if out != in && reportClasses[class] {
		w.classes[class] = true
	}
}

// noteAddr notes an address form by its canonical spelling (AddrToken's
// output with every address unmapped), so two spellings of one address are
// one input.
func (w *walker) noteAddr(dp, in, out string) {
	if c, ok := canonAddrToken(in); ok {
		in = c
	}
	w.note(dp, ClassAddress, in, out)
}

func (w *walker) replace(dp string) {
	if !w.collect {
		w.replaced[dp] = true
	}
}

// placeholder replaces non-empty free text by the fixed text (AX-7).
func (w *walker) placeholder(dp, s string) string {
	if s == "" {
		return ""
	}
	w.replace(dp)
	return Placeholder
}

// blank empties a value, keeping its presence and its JSON type.
func (w *walker) blank(dp string, v any) any {
	var zero any
	switch x := v.(type) {
	case string:
		zero = ""
	case json.Number:
		zero = json.Number("0")
	case float64:
		zero = float64(0)
	case bool:
		zero = false
	default:
		_ = x
		return v
	}
	if v != zero {
		w.replace(dp)
	}
	return zero
}

func (w *walker) mapped(dp, class, s string, f func(string) string) string {
	out := f(s)
	w.note(dp, class, s, out)
	return out
}

// account maps by the account rule; the name, sigils stripped, is what the
// ledger and the first pass record.
func (w *walker) account(dp, s string) string {
	core, ok := accountCore(s)
	if !ok {
		return s
	}
	if w.collect {
		w.homes.AddName(core)
		return s
	}
	if Kept(core) {
		w.note(dp, ClassKept, core, core)
	} else {
		w.note(dp, ClassAccount, core, w.k.Account(core))
	}
	return w.k.Account(s)
}

// host maps a DNS name; keeping wins across classes.
func (w *walker) host(dp, s string) string {
	if s == "" || w.collect {
		return s
	}
	if Kept(s) {
		w.note(dp, ClassKept, s, s)
		return s
	}
	out := w.k.Host(s)
	w.note(dp, ClassHost, strings.ToLower(s), out)
	return out
}

func (w *walker) address(dp, s string) string {
	if w.collect {
		return s
	}
	out, ok := w.k.AddrToken(s)
	if !ok {
		return w.placeholder(dp, s)
	}
	w.noteAddr(dp, s, out)
	return out
}

func (w *walker) path(dp, s string) string {
	if w.collect {
		return s
	}
	out, names := w.k.mapPath(s, w.homes)
	for _, n := range names {
		if Kept(n) {
			w.note(dp, ClassKept, n, n)
		} else {
			w.note(dp, ClassAccount, n, w.k.Account(n))
		}
	}
	w.note(dp, ClassPath, s, out)
	return out
}

// hostOrAddr is AX-4's one ordered decision: (1) an address form of §1.1;
// (2) a host form — a DNS name, host:port, transport:host[:port], rsyslog's
// [@|@@][(opts)]host[:port], a *.-prefixed wildcard, @netgroup by the
// account rule; (3) the placeholder. A kept name is kept. netgroupFirst
// reads a leading "@" as a netgroup before anything else.
func (w *walker) hostOrAddr(dp, s string, netgroupFirst bool) string {
	if s == "" {
		return ""
	}
	if Kept(s) {
		w.note(dp, ClassKept, s, s)
		return s
	}
	if netgroupFirst && s[0] == '@' {
		return w.account(dp, s)
	}
	if out, ok := w.k.AddrToken(s); ok {
		w.noteAddr(dp, s, out)
		return out
	}
	if out, ok := w.hostForm(dp, s); ok {
		return out
	}
	if s[0] == '@' && validNetgroup(s[1:]) {
		return w.account(dp, s)
	}
	return w.placeholder(dp, s)
}

func validNetgroup(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func (w *walker) hostForm(dp, s string) (string, bool) {
	if out, ok := w.hostPort(dp, s); ok {
		return out, true
	}
	for _, t := range transports {
		if rest, ok := strings.CutPrefix(s, t); ok {
			if out, ok := w.hostPort(dp, rest); ok {
				return t + out, true
			}
		}
	}
	if s[0] == '@' {
		pre, rest := "@", s[1:]
		if strings.HasPrefix(rest, "@") {
			pre, rest = "@@", rest[1:]
		}
		if strings.HasPrefix(rest, "(") {
			j := strings.IndexByte(rest, ')')
			if j < 0 {
				return "", false
			}
			pre, rest = pre+rest[:j+1], rest[j+1:]
		}
		if out, ok := w.k.AddrToken(rest); ok && rest != "" {
			w.noteAddr(dp, rest, out)
			return pre + out, true
		}
		if out, ok := w.hostPort(dp, rest); ok {
			return pre + out, true
		}
	}
	if rest, ok := strings.CutPrefix(s, "*."); ok && dnsName(rest) {
		return "*." + w.host(dp, rest), true
	}
	return "", false
}

// hostPort maps a DNS name or a DNS name with a port.
func (w *walker) hostPort(dp, s string) (string, bool) {
	if dnsName(s) {
		return w.host(dp, s), true
	}
	i := strings.LastIndexByte(s, ':')
	if i > 0 && validPort(s[i+1:]) && dnsName(s[:i]) {
		return w.host(dp, s[:i]) + s[i:], true
	}
	return "", false
}

// dnsName: letter-digit-hyphen labels of 1 to 63 characters, none all
// digits (a dotted quad that is no address is not a host), a trailing dot
// allowed.
func dnsName(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || allDigits(l) {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func validScheme(s string) bool {
	if s == "" || !(s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// url keeps the scheme, the port and the user@ syntax, maps the host by the
// host-or-address rule, the user by the account rule and the path by AX-6; a
// password, a query and a fragment are placeholdered, and a value with no
// scheme:// is placeholdered whole.
func (w *walker) url(dp, s string) string {
	if s == "" {
		return ""
	}
	i := strings.Index(s, "://")
	if i <= 0 || !validScheme(s[:i]) {
		return w.placeholder(dp, s)
	}
	rest := s[i+3:]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	auth, tail := rest[:end], rest[end:]
	var b strings.Builder
	b.WriteString(s[:i+3])
	hostport := auth
	if at := strings.LastIndexByte(auth, '@'); at >= 0 {
		user, pass, hasPass := strings.Cut(auth[:at], ":")
		b.WriteString(w.account(dp, user))
		if hasPass {
			b.WriteString(":" + w.placeholder(dp, pass))
		}
		b.WriteByte('@')
		hostport = auth[at+1:]
	}
	switch {
	case hostport == "":
	case w.collect:
		b.WriteString(hostport)
	default:
		if out, ok := w.k.AddrToken(hostport); ok {
			w.noteAddr(dp, hostport, out)
			b.WriteString(out)
		} else if out, ok := w.hostPort(dp, hostport); ok {
			b.WriteString(out)
		} else {
			b.WriteString(w.placeholder(dp, hostport))
		}
	}
	q := strings.IndexAny(tail, "?#")
	if q < 0 {
		q = len(tail)
	}
	b.WriteString(w.path(dp, tail[:q]))
	if q < len(tail) {
		b.WriteString(tail[q:q+1] + w.placeholder(dp, tail[q+1:]))
	}
	// The URL is not noted whole: its account, host, address and path parts
	// are, and a whole-URL note would collide over a placeholdered part.
	out := b.String()
	if out != s && !w.collect {
		w.classes[ClassURL] = true
	}
	return out
}

// grammar rewrites read text token by token (AX-7).
func (w *walker) grammar(dp string, g *Grammar, s string) string {
	if g == nil || g.Split != SplitWhitespace {
		if w.err == nil {
			w.err = fmt.Errorf("anonymization table: %s has no whitespace grammar", dp)
		}
		return s
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(s); {
		j := i
		if s[i] == ' ' || s[i] == '\t' {
			for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
				j++
			}
			b.WriteString(s[i:j])
			i = j
			continue
		}
		for j < len(s) && s[j] != ' ' && s[j] != '\t' {
			j++
		}
		c := g.Rest
		if n < len(g.Tokens) {
			c = g.Tokens[n]
		}
		b.WriteString(w.token(dp, c, s[i:j]))
		n++
		i = j
	}
	return b.String()
}

func (w *walker) token(dp string, c Class, tok string) string {
	if c == ClassKept || tok == "+" || tok == "-" {
		return tok
	}
	if c == "" || c == ClassGrammar {
		if w.err == nil {
			w.err = fmt.Errorf("anonymization table: %s: a grammar token needs a value class", dp)
		}
		return tok
	}
	if tok[0] == '+' || tok[0] == '-' {
		return tok[:1] + w.text(c, nil, dp, tok[1:])
	}
	return w.text(c, nil, dp, tok)
}
