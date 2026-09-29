//go:build linux

package collectors

import (
	"errors"
	"io/fs"
	"path"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/pkgfiles"
)

// The walk's capability and ACL lists (P-3). ReadDir, under
// ReadDirOptions{Xattrs: true}, opens every regular entry with an execute
// bit and hands back its security.capability and system.posix_acl_access
// attributes; this file turns them into rows and, in the join, decides
// each capability against the owning package's own declaration — rpm's
// %{FILECAPS} tag or the setcap call in a dpkg postinst. There is no
// reference list: a capability either is declared where packages declare
// capabilities, or it is not.
const (
	// declaredFromFile is declared_caps for a postinst that hands setcap its
	// set on standard input from a file the package ships: the script
	// names the path, the text is not in it.
	declaredFromFile = "(from file)"

	// dpkgPostinstGlob is what the walk may read of the maintainer
	// scripts: the postinst beside each .list, multi-arch names included.
	dpkgPostinstGlob = "/var/lib/dpkg/info/*.postinst"
)

// capabilityRow reads one executable's attributes into the two lists. An
// entry whose attributes could not be read is a skip and nothing else
// (V-39): whatever else the listing carries for it was not read from the
// file the walk listed. A capability attribute that does not decode is a
// skip too — the kernel would refuse it, so it is no capability, but a
// reader should see that the walk met one.
func (w *walker) capabilityRow(e collect.DirEntry, p string) {
	if e.XattrErr != nil {
		reason, detail := xattrSkipReason(e.XattrErr)
		w.addSkip(p, reason, detail)
		return
	}
	if e.Caps != nil {
		cs, err := decodeVfsCap(e.Caps)
		if err != nil {
			w.addSkip(p, "xattr_undecoded", err.Error())
		} else {
			// The package fields are initialised here, as the setuid rows'
			// are, so a run whose join failed still emits one shape.
			w.r.lists.addRow(capCapabilities, map[string]any{
				"path": p, "caps": capText(cs), "rootid": int(cs.RootID),
				"package": "", "package_declared": false, "declared_caps": "",
				"reference": refUnpackaged, "reason": "",
			})
		}
	}
	if e.ACL != nil {
		entries, err := decodeACL(e.ACL)
		if err != nil {
			w.addSkip(p, "xattr_undecoded", err.Error())
			return
		}
		if grants := aclWidens(entries, e.Mode); grants != nil {
			list := make([]any, 0, len(grants))
			for _, g := range grants {
				list = append(list, g)
			}
			w.r.lists.addRow(capACLGrants, map[string]any{"path": p, "entries": list})
		}
	}
}

// xattrSkipReason maps an entry's attribute failure onto walk.skipped's
// closed vocabulary: a file this process may not open is xattr_denied; one
// that is gone, is a link now, or is not the file the listing named is
// vanished with the errno in detail; any other errno is vanished too, with
// its text, so nothing is lost and the vocabulary stays closed.
func xattrSkipReason(err error) (reason, detail string) {
	switch {
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM), errors.Is(err, fs.ErrPermission):
		return "xattr_denied", ""
	case errors.Is(err, collect.ErrVanished):
		return "vanished", "the entry changed between listing and opening"
	}
	var errno unix.Errno
	if errors.As(err, &errno) {
		return "vanished", errno.Error()
	}
	return "vanished", err.Error()
}

// aclWidens is the access-ACL entries that grant a named user or group
// write or execute beyond what the owning group's own entry grants, after
// the mask (acl(5): a named entry's effective rights are its rights and the
// mask). The comparison is against the group:: entry because the mode's
// group bits ARE the mask once an ACL has named entries, so nothing could
// ever exceed them; group:: is what those bits meant before the ACL. A
// list with no group:: entry (not one the kernel writes) falls back to the
// mode's group bits. Read is never a widening here: this list is about who
// may change or run an executable. nil when no entry widens.
func aclWidens(entries []string, mode uint32) []string {
	mask, groupObj := 7, int(mode>>3)&7
	for _, e := range entries {
		switch {
		case strings.HasPrefix(e, "mask::"):
			mask = aclPerm(e)
		case strings.HasPrefix(e, "group::"):
			groupObj = aclPerm(e)
		}
	}
	var out []string
	for _, e := range entries {
		named := (strings.HasPrefix(e, "user:") && !strings.HasPrefix(e, "user::")) ||
			(strings.HasPrefix(e, "group:") && !strings.HasPrefix(e, "group::"))
		if !named {
			continue
		}
		if aclPerm(e)&mask&3&^groupObj != 0 {
			out = append(out, e)
		}
	}
	return out
}

// aclPerm reads the rwx triple decodeACL renders at the end of an entry.
func aclPerm(entry string) int {
	if len(entry) < 3 {
		return 0
	}
	t, perm := entry[len(entry)-3:], 0
	if t[0] == 'r' {
		perm |= 4
	}
	if t[1] == 'w' {
		perm |= 2
	}
	if t[2] == 'x' {
		perm |= 1
	}
	return perm
}

// declaresCaps says whether a declared text is the set a row carries, triple
// against triple (V-3): the row's caps is capText's own output, which
// parses back to the attribute's set.
func declaresCaps(row map[string]any, declared string) bool {
	if declared == "" {
		return false
	}
	have, err := parseCapText(rowField(row, "caps"))
	if err != nil {
		return false
	}
	want, err := parseCapText(declared)
	return err == nil && sameCaps(have, want)
}

// applyRPMCaps decides the capability rows from rpm's file table: the
// %{FILECAPS} column is the package's declaration, in its build host's
// libcap spelling. A path the table does not hold stays unpackaged.
func applyRPMCaps(r *walkResult, table map[string]rpmFile) {
	for _, row := range r.lists.capabilities {
		f, ok := table[rowField(row, "path")]
		if !ok {
			continue
		}
		row["package"] = f.pkg
		row["package_declared"] = declaresCaps(row, f.caps)
		row["declared_caps"] = f.caps
		row["reference"] = refRPMDB
	}
}

// postinstCap is one path a postinst hands setcap: the caps text as the
// script wrote it, or FromFile when the script feeds setcap the set from a
// file on standard input.
type postinstCap struct {
	Path, Caps string
	FromFile   bool
}

// postinstPath is the maintainer script beside a .list, multi-arch
// qualifier and all: libgstreamer1.0-0:amd64.list -> …:amd64.postinst.
func postinstPath(listFile string) string {
	return strings.TrimSuffix(listFile, ".list") + ".postinst"
}

// readPostinst reads and parses the postinst beside a .list. It never fails
// the join (V-22): a package's script says what that package declares and
// nothing about any other, so an unreadable one is that row's answer alone.
func (j *dpkgJoin) readPostinst(listFile string) ([]postinstCap, error) {
	if listFile == "" {
		return nil, fs.ErrNotExist
	}
	data, _, err := j.a.ReadFile(postinstPath(listFile), dpkgJoinReadLimit)
	if err != nil {
		return nil, err
	}
	return parsePostinstSetcap(data), nil
}

// applyDpkgCaps decides the capability rows on a dpkg host. A .deb cannot
// carry an attribute, so the package that owns the path sets it at install
// time from its postinst; the script is read once per package, and a row
// is declared when the script's setcap names the path with the same set,
// or names it with a set read from a file. A missing script declares
// nothing and says nothing more (most packages have none); an unreadable
// one declares nothing and says why.
func (j *dpkgJoin) applyDpkgCaps(r *walkResult) {
	type read struct {
		caps []postinstCap
		err  error
	}
	cache := map[string]read{}
	for _, row := range r.lists.capabilities {
		p := rowField(row, "path")
		pkg, owned := j.idx.owner[p]
		if !owned {
			continue
		}
		row["package"] = pkg
		row["package_declared"] = false
		row["declared_caps"] = ""
		row["reference"] = refPostinst
		lf := j.idx.listFile[p]
		rd, seen := cache[lf]
		if !seen {
			rd.caps, rd.err = j.readPostinst(lf)
			cache[lf] = rd
		}
		if rd.err != nil {
			if !errors.Is(rd.err, fs.ErrNotExist) {
				row["reason"] = postinstPath(lf) + ": " + collect.FromReadError(rd.err, collect.ReadMeta{}).Reason
			}
			continue
		}
		declared, text := j.postinstDecides(row, p, rd.caps)
		row["package_declared"] = declared
		row["declared_caps"] = text
	}
}

// postinstDecides matches a script's setcap calls to one row. The script
// names the path as the package ships it — pre-merge, or before a diversion
// moved it — so a name matches when it canonicalises to the row's path or
// to the name the package's .list gave it. The first call that declares the
// row's set wins; failing that, the first call that names the path says
// what the package did declare.
func (j *dpkgJoin) postinstDecides(row map[string]any, p string, calls []postinstCap) (bool, string) {
	shipped := j.idx.listPath[p]
	first, named := "", false
	for _, c := range calls {
		canon := pkgfiles.CanonicalUsr(c.Path, j.merged)
		if canon != p && (shipped == "" || canon != shipped) {
			continue
		}
		if c.FromFile {
			return true, declaredFromFile
		}
		if declaresCaps(row, c.Caps) {
			return true, c.Caps
		}
		if !named {
			first, named = c.Caps, true
		}
	}
	return false, first
}

// parsePostinstSetcap finds the setcap calls in a maintainer script, in the
// three forms a package uses (spec P-3):
//
//	setcap <caps> /literal/path
//	setcap <caps> $NAME            NAME=/literal/path earlier in the script,
//	                               or NAME=$(dpkg-divert --truename /path)
//	setcap [-q] - /path < file     the set read from a file
//
// It is a reader of the shell's words, not a shell: logical lines (a
// trailing backslash continues one), '#' comments, quotes, the command
// separators, redirections and here-documents are honoured, so a setcap in a
// comment, an echo or a here-document is not a call. A command is a setcap
// call when its first word — after if, !, then, else, elif, do, while or
// until — is setcap; options -q, -v, -f, -h, --license and -n <rootid> are
// passed over, and every (caps, path) pair after them is a call, except a
// -r removal. A path or a caps text that uses a variable the script did not
// assign literally is skipped rather than guessed.
func parsePostinstSetcap(data []byte) []postinstCap {
	vars := map[string]string{}
	var out []postinstCap
	lines := shellLogicalLines(data)
	for i := 0; i < len(lines); i++ {
		toks := shellWords(lines[i], vars)
		var heredocs []shTok
		for _, cmd := range splitShellCommands(toks) {
			words, heres := shellCommandWords(cmd)
			heredocs = append(heredocs, heres...)
			out = append(out, setcapCalls(words, vars)...)
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
func shellWords(line string, vars map[string]string) []shTok {
	var out []shTok
	var cur strings.Builder
	inWord, known := false, true
	flush := func() {
		if inWord {
			out = append(out, shTok{text: cur.String(), known: known})
		}
		cur.Reset()
		inWord, known = false, true
	}
	emit := func(op string) {
		flush()
		out = append(out, shTok{op: op, known: true})
	}
	expand := func(i int) int {
		v, ok, next := shellExpansion(line, i, vars)
		cur.WriteString(v)
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
// returns the value, whether it was resolved, and the index after it.
func shellExpansion(line string, i int, vars map[string]string) (string, bool, int) {
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
			return "", false, len(line)
		}
		inner := strings.Fields(rest[1:j])
		next := i + 1 + j + 1
		if len(inner) == 3 && inner[0] == "dpkg-divert" && inner[1] == "--truename" && literalAbsolute(inner[2]) {
			// The truename of a path is the path the package ships; the
			// join follows the diversion from there, as it does for .list
			// lines.
			return inner[2], true, next
		}
		return "", false, next
	case strings.HasPrefix(rest, "{"):
		end := strings.IndexByte(rest, '}')
		if end < 0 {
			return "", false, len(line)
		}
		v, ok := vars[rest[1:end]]
		return v, ok, i + 1 + end + 1
	}
	n := 0
	for n < len(rest) && (rest[n] == '_' || rest[n] >= 'a' && rest[n] <= 'z' || rest[n] >= 'A' && rest[n] <= 'Z' || n > 0 && rest[n] >= '0' && rest[n] <= '9') {
		n++
	}
	if n == 0 {
		if rest != "" && strings.IndexByte("0123456789?#@*-$!", rest[0]) >= 0 {
			return "", false, i + 2
		}
		return "$", true, i + 1
	}
	v, ok := vars[rest[:n]]
	return v, ok, i + 1 + n
}

func literalAbsolute(s string) bool {
	return strings.HasPrefix(s, "/") && !strings.ContainsAny(s, "$`\"'\\")
}

// splitShellCommands cuts a line's tokens at the command separators.
func splitShellCommands(toks []shTok) [][]shTok {
	var out [][]shTok
	var cur []shTok
	for _, t := range toks {
		switch t.op {
		case ";", ";;", "&", "&&", "|", "||", "(", ")":
			out = append(out, cur)
			cur = nil
			continue
		}
		cur = append(cur, t)
	}
	return append(out, cur)
}

// shellCommandWords is a command's words with its redirections taken out.
// An input redirection's target is kept as a word marked by op "<" so a
// setcap reading its set from a file can be recognised; a here-document's
// delimiter is returned so its body can be skipped.
func shellCommandWords(cmd []shTok) (words, heredocs []shTok) {
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
		case "<<", "<<-":
			heredocs = append(heredocs, shTok{text: cmd[i].text, op: t.op})
		}
	}
	return words, heredocs
}

// setcapCalls reads one command: an assignment updates what the script has
// assigned, and a setcap call yields its (caps, path) pairs.
func setcapCalls(words []shTok, vars map[string]string) []postinstCap {
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
			vars[name] = value
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
		if !target.known || !literalAbsolute(target.text) || (caps.known && caps.text == "-r") {
			continue
		}
		p := path.Clean(target.text)
		if caps.known && caps.text == "-" {
			out = append(out, postinstCap{Path: p, FromFile: true})
			continue
		}
		if !caps.known {
			continue
		}
		out = append(out, postinstCap{Path: p, Caps: caps.text})
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
