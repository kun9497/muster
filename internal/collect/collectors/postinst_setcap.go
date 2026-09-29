package collectors

import (
	"path"
	"strings"
)

// The postinst reader of the capability join (P-3). It has no build tag: it
// reads bytes, touches nothing, and is tested on every platform, as caps.go
// is.

// postinstCap is one setcap call a postinst makes: the path and the caps
// text as the script wrote them, or FromFile when the script feeds setcap
// its set from a file or a pipe on standard input. Truename says the path
// came from dpkg-divert --truename, so it names wherever dpkg put the
// package's own file, diverted or not. Unresolved marks a call muster
// could not read — a path or a caps text built from something the reader
// does not evaluate — which declares nothing but is not silence either.
type postinstCap struct {
	Path, Caps string
	FromFile   bool
	Truename   bool
	Unresolved bool
}

// shVar is what the script assigned to a name, and whether the value came
// from dpkg-divert --truename.
type shVar struct {
	value    string
	truename bool
}

// parsePostinstSetcap finds the setcap calls in a maintainer script, in the
// three forms a package uses (spec P-3):
//
//	setcap <caps> /literal/path
//	setcap <caps> $NAME            NAME=/literal/path earlier in the script,
//	                               or NAME=$(dpkg-divert --truename /path)
//	setcap [-q] - /path < file     the set read from a file (or a pipe)
//
// It is a reader of the shell's words, not a shell: logical lines (a
// trailing backslash continues one), '#' comments, quotes, the command
// separators, redirections and here-documents are honoured, so a setcap in a
// comment, an echo or a here-document is not a call. A command is a setcap
// call when its first word — after if, !, then, else, elif, do, while or
// until — is setcap; options -q, -v, -f, -h, --license and -n <rootid> are
// passed over, and every (caps, path) pair after them is a call, except a
// -r removal. A pair whose path or caps text uses a variable the script did
// not assign literally, or a "-" set with nothing feeding standard input,
// is reported Unresolved rather than guessed.
func parsePostinstSetcap(data []byte) []postinstCap {
	vars := map[string]shVar{}
	var out []postinstCap
	lines := shellLogicalLines(data)
	for i := 0; i < len(lines); i++ {
		toks := shellWords(lines[i], vars)
		var heredocs []shTok
		for _, cmd := range splitShellCommands(toks) {
			words, heres, stdin := shellCommandWords(cmd.toks)
			heredocs = append(heredocs, heres...)
			out = append(out, setcapCalls(words, vars, stdin || cmd.piped)...)
		}
		// A here-document's body is data, not commands.
		for _, h := range heredocs {
			for i+1 < len(lines) {
				i++
				body := lines[i]
				if h.op == "<<-" {
					body = strings.TrimLeft(body, "\t")
				}
				if body == h.text {
					break
				}
			}
		}
	}
	return out
}

// shTok is one word or operator of a shell line. known is false when the
// word used an expansion the reader could not resolve.
type shTok struct {
	text  string
	op    string
	known bool
	// truename says the word took its value from dpkg-divert --truename,
	// directly or through a variable assigned from one.
	truename bool
}

// shellLogicalLines splits a script into lines, joining a line that ends in
// a backslash to the next and dropping a carriage return.
func shellLogicalLines(data []byte) []string {
	var out []string
	var cur strings.Builder
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSuffix(l, "\r")
		if strings.HasSuffix(l, "\\") {
			cur.WriteString(l[:len(l)-1])
			continue
		}
		cur.WriteString(l)
		out = append(out, cur.String())
		cur.Reset()
	}
	if cur.Len() != 0 {
		out = append(out, cur.String())
	}
	return out
}

// shellWords splits one logical line into words and operators, removing
// quotes and resolving $NAME, ${NAME} and $(dpkg-divert --truename /path)
// from what the script has assigned so far.
func shellWords(line string, vars map[string]shVar) []shTok {
	var out []shTok
	var cur strings.Builder
	inWord, known, truename := false, true, false
	flush := func() {
		if inWord {
			out = append(out, shTok{text: cur.String(), known: known, truename: truename})
		}
		cur.Reset()
		inWord, known, truename = false, true, false
	}
	emit := func(op string) {
		flush()
		out = append(out, shTok{op: op, known: true})
	}
	expand := func(i int) int {
		v, ok, tn, next := shellExpansion(line, i, vars)
		cur.WriteString(v)
		if tn {
			truename = true
		}
		if !ok {
			known = false
		}
		inWord = true
		return next
	}
	for i := 0; i < len(line); {
		c := line[i]
		switch {
		case c == ' ' || c == '\t':
			flush()
			i++
		case c == '#' && !inWord:
			return out // a comment runs to the end of the line
		case c == '\\':
			if i+1 < len(line) {
				cur.WriteByte(line[i+1])
			}
			inWord = true
			i += 2
		case c == '\'':
			end := strings.IndexByte(line[i+1:], '\'')
			if end < 0 {
				end = len(line) - i - 1
			}
			cur.WriteString(line[i+1 : i+1+end])
			inWord = true
			i += end + 2
		case c == '"':
			inWord = true
			i++
			for i < len(line) && line[i] != '"' {
				switch {
				case line[i] == '\\' && i+1 < len(line) && strings.IndexByte("$`\"\\", line[i+1]) >= 0:
					cur.WriteByte(line[i+1])
					i += 2
				case line[i] == '$':
					i = expand(i)
				case line[i] == '`':
					known = false
					end := strings.IndexByte(line[i+1:], '`')
					if end < 0 {
						i = len(line)
					} else {
						i += end + 2
					}
				default:
					cur.WriteByte(line[i])
					i++
				}
			}
			i++
		case c == '$':
			i = expand(i)
		case c == '`':
			known, inWord = false, true
			end := strings.IndexByte(line[i+1:], '`')
			if end < 0 {
				i = len(line)
			} else {
				i += end + 2
			}
		case c == ';' || c == '&' || c == '|' || c == '(' || c == ')':
			if i+1 < len(line) && line[i+1] == c && c != '(' && c != ')' {
				emit(string([]byte{c, c}))
				i += 2
				continue
			}
			emit(string(c))
			i++
		case c == '<':
			flush()
			switch {
			case strings.HasPrefix(line[i:], "<<-"):
				emit("<<-")
				i += 3
			case strings.HasPrefix(line[i:], "<<"):
				emit("<<")
				i += 2
			default:
				emit("<")
				i++
			}
		case c == '>':
			if inWord && isDigits(cur.String()) {
				cur.Reset() // an fd number: 2>/dev/null
				inWord = false
			}
			emit(">")
			i++
			for i < len(line) && (line[i] == '>' || line[i] == '&') {
				i++
			}
		default:
			cur.WriteByte(c)
			inWord = true
			i++
		}
	}
	flush()
	return out
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// shellExpansion resolves the expansion that starts at line[i] ('$'). It
// returns the value, whether it was resolved, whether it came from
// dpkg-divert --truename, and the index after it.
func shellExpansion(line string, i int, vars map[string]shVar) (string, bool, bool, int) {
	rest := line[i+1:]
	switch {
	case strings.HasPrefix(rest, "("):
		depth, j := 0, 0
		for ; j < len(rest); j++ {
			if rest[j] == '(' {
				depth++
			} else if rest[j] == ')' {
				depth--
				if depth == 0 {
					break
				}
			}
		}
		if j >= len(rest) {
			return "", false, false, len(line)
		}
		inner := strings.Fields(rest[1:j])
		next := i + 1 + j + 1
		if len(inner) == 3 && inner[0] == "dpkg-divert" && inner[1] == "--truename" && literalAbsolute(inner[2]) {
			// The truename of a path is the path the package ships; the
			// join follows the diversion from there, as it does for .list
			// lines.
			return inner[2], true, true, next
		}
		return "", false, false, next
	case strings.HasPrefix(rest, "{"):
		end := strings.IndexByte(rest, '}')
		if end < 0 {
			return "", false, false, len(line)
		}
		v, ok := vars[rest[1:end]]
		return v.value, ok, v.truename, i + 1 + end + 1
	}
	n := 0
	for n < len(rest) && (rest[n] == '_' || rest[n] >= 'a' && rest[n] <= 'z' || rest[n] >= 'A' && rest[n] <= 'Z' || n > 0 && rest[n] >= '0' && rest[n] <= '9') {
		n++
	}
	if n == 0 {
		if rest != "" && strings.IndexByte("0123456789?#@*-$!", rest[0]) >= 0 {
			return "", false, false, i + 2
		}
		return "$", true, false, i + 1
	}
	v, ok := vars[rest[:n]]
	return v.value, ok, v.truename, i + 1 + n
}

func literalAbsolute(s string) bool {
	return strings.HasPrefix(s, "/") && !strings.ContainsAny(s, "$`\"'\\")
}

// shCmd is one command of a line and whether a pipe feeds it.
type shCmd struct {
	toks  []shTok
	piped bool
}

// splitShellCommands cuts a line's tokens at the command separators; a
// command after a "|" is marked piped.
func splitShellCommands(toks []shTok) []shCmd {
	var out []shCmd
	cur := shCmd{}
	for _, t := range toks {
		switch t.op {
		case ";", ";;", "&", "&&", "|", "||", "(", ")":
			out = append(out, cur)
			cur = shCmd{piped: t.op == "|"}
			continue
		}
		cur.toks = append(cur.toks, t)
	}
	return append(out, cur)
}

// shellCommandWords is a command's words with its redirections taken out
// and their targets dropped. stdin says the command has an input
// redirection ("<"), which is what feeds "setcap -" its set; a
// here-document's delimiter is returned so its body can be skipped.
func shellCommandWords(cmd []shTok) (words, heredocs []shTok, stdin bool) {
	for i := 0; i < len(cmd); i++ {
		t := cmd[i]
		if t.op == "" {
			words = append(words, t)
			continue
		}
		if i+1 >= len(cmd) || cmd[i+1].op != "" {
			continue
		}
		i++
		switch t.op {
		case "<":
			stdin = true
		case "<<", "<<-":
			heredocs = append(heredocs, shTok{text: cmd[i].text, op: t.op})
		}
	}
	return words, heredocs, stdin
}

// setcapCalls reads one command: an assignment updates what the script has
// assigned, and a setcap call yields its (caps, path) pairs. fed says
// something feeds the command's standard input.
func setcapCalls(words []shTok, vars map[string]shVar, fed bool) []postinstCap {
	for len(words) > 0 {
		switch words[0].text {
		case "if", "!", "then", "else", "elif", "do", "while", "until", "{", "}", "export", "local", "readonly":
			words = words[1:]
			continue
		}
		break
	}
	// Leading NAME=value words are assignments; one standing alone sets a
	// variable for the rest of the script.
	for len(words) > 0 {
		name, value, ok := strings.Cut(words[0].text, "=")
		if !ok || !shellName(name) {
			break
		}
		if words[0].known && literalAbsolute(value) {
			vars[name] = shVar{value: value, truename: words[0].truename}
		} else {
			delete(vars, name)
		}
		words = words[1:]
	}
	if len(words) == 0 || !words[0].known || path.Base(words[0].text) != "setcap" {
		return nil
	}
	args := words[1:]
	for len(args) > 0 && args[0].known {
		switch args[0].text {
		case "-q", "-v", "-f", "-h", "--license":
			args = args[1:]
			continue
		case "-n":
			if len(args) < 2 {
				return nil
			}
			args = args[2:]
			continue
		}
		break
	}
	var out []postinstCap
	for ; len(args) >= 2; args = args[2:] {
		caps, target := args[0], args[1]
		if caps.known && caps.text == "-r" {
			continue
		}
		if !target.known || !literalAbsolute(target.text) {
			out = append(out, postinstCap{Unresolved: true})
			continue
		}
		c := postinstCap{Path: path.Clean(target.text), Truename: target.truename}
		switch {
		case caps.known && caps.text == "-" && fed:
			c.FromFile = true
		case caps.known && caps.text != "-":
			c.Caps = caps.text
		default:
			c.Unresolved = true
		}
		out = append(out, c)
	}
	return out
}

func shellName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}
