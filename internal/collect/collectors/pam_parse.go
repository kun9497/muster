//go:build linux

package collectors

import (
	"errors"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	pamDir        = "/etc/pam.d"
	pamDirGlob    = "/etc/pam.d/*"
	authselectDir = "/etc/authselect"
	maxPAMDepth   = 8
)

// authselectManaged are the pam.d names authselect replaces with symlinks
// into /etc/authselect. The primitive refuses a symlink, so the original
// is read by name — declared, never resolved with readlink.
var authselectManaged = []string{"system-auth", "password-auth", "fingerprint-auth", "smartcard-auth", "postlogin"}

// pamServices are the login-facing services whose expanded stacks are
// published; the derived facts read from these and nothing else.
var pamServices = []string{"login", "sshd", "su", "sudo", "passwd", "other"}

// pamLine is one expanded stack line.
type pamLine struct {
	Service string
	Type    string // auth | account | password | session (a leading "-" is stripped)
	Control string // required | requisite | sufficient | optional | [ ... ] verbatim
	Module  string
	Args    []string
	Path    string
	Line    int
}

// pamDirective is one parsed line before expansion: a module line, or an
// include of another file.
type pamDirective struct {
	line     pamLine
	include  string // the file to include; "" for a module line
	sameType bool   // include/substack splice the directive's type only; @include splices every type
}

// pamTokens splits a pam.d line into fields, keeping a bracketed control
// field such as "[success=1 default=ignore]" as one token.
func pamTokens(line string) []string {
	f := strings.Fields(line)
	var out []string
	for i := 0; i < len(f); i++ {
		t := f[i]
		if strings.HasPrefix(t, "[") && !strings.HasSuffix(t, "]") {
			j := i + 1
			for ; j < len(f); j++ {
				t += " " + f[j]
				if strings.HasSuffix(f[j], "]") {
					break
				}
			}
			i = j
		}
		out = append(out, t)
	}
	return out
}

// parsePAMFile parses one file. Comments and blank lines are skipped; a
// line with fewer than three fields is malformed and skipped (libpam logs
// and ignores it too).
func parsePAMFile(data []byte, service, filePath string) []pamDirective {
	var out []pamDirective
	for i, raw := range splitLines(data) {
		l := strings.TrimSpace(raw)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if strings.HasPrefix(l, "@include") {
			if f := strings.Fields(l); len(f) >= 2 {
				out = append(out, pamDirective{include: f[1], line: pamLine{Service: service, Path: filePath, Line: i + 1}})
			}
			continue
		}
		f := pamTokens(l)
		if len(f) < 3 {
			continue
		}
		typ := strings.ToLower(strings.TrimPrefix(f[0], "-"))
		ctl := f[1]
		if ctl == "include" || ctl == "substack" {
			out = append(out, pamDirective{include: f[2], sameType: true, line: pamLine{Service: service, Type: typ, Path: filePath, Line: i + 1}})
			continue
		}
		args := []string{}
		args = append(args, f[3:]...)
		out = append(out, pamDirective{line: pamLine{Service: service, Type: typ, Control: ctl, Module: f[2], Args: args, Path: filePath, Line: i + 1}})
	}
	return out
}

// pamExpander expands one service at a time and remembers every problem
// that makes the result incomplete.
type pamExpander struct {
	a          collect.Access
	problems   []string
	authselect bool
	read       map[string]bool // files that were read at least once
}

func newPAMExpander(a collect.Access) *pamExpander {
	return &pamExpander{a: a, read: map[string]bool{}}
}

// resolve turns an include target into a pam.d path: a bare name lives in
// /etc/pam.d; an absolute path is used as given.
func resolve(target string) string {
	if strings.HasPrefix(target, "/") {
		return path.Clean(target)
	}
	return pamDir + "/" + target
}

// readReason is a read error's text with the path the primitive already put
// in front of it stripped, so a caller that prefixes the path itself writes
// it exactly once (D16): the host says "/etc/pam.d/x: symbolic link in
// path", not "/etc/pam.d/x: /etc/pam.d/x: symbolic link in path".
func readReason(p string, err error) string {
	return strings.TrimPrefix(err.Error(), p+": ")
}

// readService reads a pam.d file, falling back to the authselect original
// when the pam.d entry is a symlink of a managed name. It returns the path
// actually read.
func (x *pamExpander) readService(p string) ([]byte, string, error) {
	data, _, err := x.a.ReadFile(p, readLimit)
	if err != nil && errors.Is(err, collect.ErrSymlink) && path.Dir(p) == pamDir && slices.Contains(authselectManaged, path.Base(p)) {
		alt := authselectDir + "/" + path.Base(p)
		if data2, _, err2 := x.a.ReadFile(alt, readLimit); err2 == nil {
			x.authselect = true
			return data2, alt, nil
		}
	}
	return data, p, err
}

func (x *pamExpander) problem(msg string) {
	x.problems = append(x.problems, msg)
}

// inputs is every file the expander actually read, sorted by path, as the
// Inputs of a derived source (R147). It is the authselect original that
// appears here, never the /etc/pam.d symlink that was refused.
func (x *pamExpander) inputs() []facts.Source {
	paths := make([]string, 0, len(x.read))
	for p := range x.read {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	out := make([]facts.Source, 0, len(paths))
	for _, p := range paths {
		out = append(out, facts.Source{Kind: "file", Path: p})
	}
	return out
}

// expand returns the fully expanded stack of /etc/pam.d/<name>. The service
// file itself is level 1, so a chain of more than maxPAMDepth files trips
// the depth guard in expandFile.
func (x *pamExpander) expand(name string) []pamLine {
	return x.expandFile(pamDir+"/"+name, name, "", 1, map[string]bool{})
}

// expandFile expands one file. typeFilter keeps only lines of that type
// (the include/substack rule); "" keeps every type (@include, or the top
// level). seen holds the files on the current include chain, so a loop is
// reported once and stops.
func (x *pamExpander) expandFile(p, service, typeFilter string, depth int, seen map[string]bool) []pamLine {
	if depth > maxPAMDepth {
		x.problem(p + ": include nesting deeper than " + strconv.Itoa(maxPAMDepth) + " levels")
		return nil
	}
	if seen[p] {
		x.problem(p + ": include loop")
		return nil
	}
	if !declared(x.a, p) {
		x.problem(p + ": include outside the collector's declaration")
		return nil
	}
	data, used, err := x.readService(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			x.problem(p + ": included file does not exist")
		} else {
			x.problem(p + ": " + readReason(p, err))
		}
		return nil
	}
	x.read[used] = true
	seen[p] = true
	defer delete(seen, p)
	var out []pamLine
	for _, d := range parsePAMFile(data, service, used) {
		if typeFilter != "" && d.line.Type != "" && d.line.Type != typeFilter {
			continue
		}
		if d.include != "" {
			filter := typeFilter
			if d.sameType {
				filter = d.line.Type
			}
			out = append(out, x.expandFile(resolve(d.include), service, filter, depth+1, seen)...)
			continue
		}
		out = append(out, d.line)
	}
	return out
}

// stackRecords renders expanded lines as the pam.stacks value.
func stackRecords(lines []pamLine) []any {
	out := []any{} // R50: never nil
	for _, l := range lines {
		args := []any{}
		for _, a := range l.Args {
			args = append(args, a)
		}
		out = append(out, map[string]any{
			"service": l.Service, "type": l.Type, "control": l.Control, "module": l.Module,
			"args": args, "path": l.Path, "line": l.Line,
		})
	}
	return out
}

// linesOf selects the lines of one type that load one module. The module is
// matched by basename (D17c), so an absolute module path such as
// /lib64/security/pam_unix.so is the same module as pam_unix.so; the
// published "module" field keeps whatever the file said.
func linesOf(lines []pamLine, typ, module string) []pamLine {
	var out []pamLine
	for _, l := range lines {
		if l.Type == typ && path.Base(l.Module) == module {
			out = append(out, l)
		}
	}
	return out
}

// hasArg reports whether a flag argument (or a key=value with that key) is
// present.
func hasArg(args []string, name string) bool {
	_, ok := argValue(args, name)
	return ok
}

// argValue returns the value of a key=value argument, "" for a bare flag,
// and false when the argument is absent. The last occurrence wins, as it
// does for the modules themselves.
func argValue(args []string, name string) (string, bool) {
	val, found := "", false
	for _, a := range args {
		if a == name {
			val, found = "", true
			continue
		}
		if strings.HasPrefix(a, name+"=") {
			val, found = strings.TrimPrefix(a, name+"="), true
		}
	}
	return val, found
}
