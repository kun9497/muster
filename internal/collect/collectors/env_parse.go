//go:build linux

package collectors

import (
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/collect"
)

type shellAssignment struct {
	Kind                                      string // tmout | umask | path
	Value                                     string
	Path                                      string
	Line                                      int
	Exported, Readonly, Conditional, Symbolic bool
	Scope                                     string
}

// parseShellFile scans a POSIX/bash startup file for TMOUT, umask and PATH.
// It tracks a coarse conditional depth: a line that opens an if/for/while/
// case block, or is joined with && or ||, raises depth; `fi`/`done`/`esac`
// lower it. An assignment at depth>0 is conditional (muster cannot prove it
// always runs). This is deliberately structural, not a shell interpreter.
func parseShellFile(data []byte, p string) []shellAssignment {
	var out []shellAssignment
	depth := 0
	scope := "system"
	if strings.HasPrefix(p, "/root/") {
		scope = "root"
	}
	for i, raw := range splitLines(data) {
		full := strings.TrimSpace(cutComment(raw))
		if full == "" {
			continue
		}
		// blockDelta is computed on the whole physical line; conditional depth
		// applies to the statements on it.
		opens, closes := blockDelta(full)
		conditional := depth > 0
		// A single physical line may hold several statements separated by an
		// unquoted `;` (e.g. `TMOUT=600; export TMOUT`); scan each (R184).
		for _, line := range splitStatements(full) {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			// TMOUT: a declaration keyword (declare/typeset/export/readonly
			// with optional -x/-r/-xr flags) assigning it, else a bare
			// assignment, else a bare export/readonly of the name (R184).
			if v, exported, readonly, ok := declAssignment(line, "TMOUT"); ok {
				out = append(out, shellAssignment{Kind: "tmout", Value: v, Path: p, Line: i + 1,
					Exported: exported, Readonly: readonly, Conditional: conditional})
			} else if v, ok := assignmentValue(line, "TMOUT"); ok {
				out = append(out, shellAssignment{Kind: "tmout", Value: v, Path: p, Line: i + 1,
					Exported: strings.HasPrefix(line, "export "), Conditional: conditional})
			} else if name, ok := exportName(line); ok && name == "TMOUT" {
				out = append(out, shellAssignment{Kind: "tmout", Value: "", Path: p, Line: i + 1, Exported: true, Conditional: conditional})
			} else if name, ok := readonlyName(line); ok && name == "TMOUT" {
				out = append(out, shellAssignment{Kind: "tmout", Value: "", Path: p, Line: i + 1, Readonly: true, Conditional: conditional})
			}
			// umask
			if fields := strings.Fields(line); len(fields) >= 2 && (fields[0] == "umask" || (fields[0] == "builtin" && fields[1] == "umask")) {
				val := fields[len(fields)-1]
				out = append(out, shellAssignment{Kind: "umask", Value: val, Path: p, Line: i + 1,
					Symbolic: !isOctalMask(val), Conditional: conditional, Scope: scope})
			}
			// PATH: same declaration-keyword forms, then a bare assignment.
			if v, exported, _, ok := declAssignment(line, "PATH"); ok {
				out = append(out, shellAssignment{Kind: "path", Value: v, Path: p, Line: i + 1, Exported: exported, Conditional: conditional, Scope: scope})
			} else if v, ok := assignmentValue(line, "PATH"); ok {
				out = append(out, shellAssignment{Kind: "path", Value: v, Path: p, Line: i + 1, Conditional: conditional, Scope: scope})
			}
		}
		depth += opens - closes
		if depth < 0 {
			depth = 0
		}
	}
	return out
}

// splitStatements splits a line on unquoted `;` so several statements on one
// physical line are scanned independently, e.g. `TMOUT=600; export TMOUT` (R184).
func splitStatements(line string) []string {
	out := []string{}
	inS, inD := false, false
	start := 0
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS {
				inD = !inD
			}
		case ';':
			if !inS && !inD {
				out = append(out, line[start:i])
				start = i + 1
			}
		}
	}
	return append(out, line[start:])
}

// declAssignment recognises a declaration keyword (declare, typeset, export or
// readonly) with optional -x/-r/-xr flags assigning name — `declare -xr
// TMOUT=600`, `export -r PATH=…`, `readonly TMOUT=600`, `export TMOUT=600` —
// and reports the value plus whether the form exports (-x, or the `export`
// keyword) and/or makes the name readonly (-r, or the `readonly` keyword) (R184).
func declAssignment(line, name string) (value string, exported, readonly, ok bool) {
	f := strings.Fields(line)
	if len(f) == 0 {
		return "", false, false, false
	}
	switch f[0] {
	case "export":
		exported = true
	case "readonly":
		readonly = true
	case "declare", "typeset":
	default:
		return "", false, false, false
	}
	rest := f[1:]
	for len(rest) > 0 && strings.HasPrefix(rest[0], "-") {
		if strings.Contains(rest[0], "x") {
			exported = true
		}
		if strings.Contains(rest[0], "r") {
			readonly = true
		}
		rest = rest[1:]
	}
	prefix := name + "="
	if len(rest) == 0 || !strings.HasPrefix(rest[0], prefix) {
		return "", false, false, false
	}
	v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(rest[0], prefix)), `"'`)
	return v, exported, readonly, true
}

// cutComment drops an unquoted trailing comment. A `#` inside single or
// double quotes is kept; this is a coarse scan, not a shell lexer, so a `#`
// after an odd number of quotes is treated as literal.
func cutComment(line string) string {
	inS, inD := false, false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS {
				inD = !inD
			}
		case '#':
			if !inS && !inD && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
				return line[:i]
			}
		}
	}
	return line
}

// assignmentValue returns the RHS of `name=value` or `export name=value`,
// with surrounding quotes stripped. ok is false when the line is not an
// assignment to name.
func assignmentValue(line, name string) (string, bool) {
	l := strings.TrimPrefix(line, "export ")
	l = strings.TrimSpace(l)
	prefix := name + "="
	if !strings.HasPrefix(l, prefix) {
		return "", false
	}
	v := strings.TrimSpace(l[len(prefix):])
	v = strings.Trim(v, `"'`)
	return v, true
}

func exportName(line string) (string, bool) {
	if !strings.HasPrefix(line, "export ") {
		return "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, "export "))
	if i := strings.IndexByte(rest, '='); i >= 0 {
		return rest[:i], true
	}
	return strings.Fields(rest)[0], true
}

func readonlyName(line string) (string, bool) {
	if !strings.HasPrefix(line, "readonly ") {
		return "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, "readonly "))
	if i := strings.IndexByte(rest, '='); i >= 0 {
		return rest[:i], true
	}
	return strings.Fields(rest)[0], true
}

func isOctalMask(v string) bool {
	if len(v) < 3 || len(v) > 4 {
		return false
	}
	_, err := strconv.ParseInt(v, 8, 32)
	return err == nil
}

// blockDelta counts shell block openers and closers on one line.
func blockDelta(line string) (opens, closes int) {
	f := strings.Fields(line)
	for _, w := range f {
		switch w {
		case "if", "for", "while", "until", "case":
			opens++
		case "fi", "done", "esac":
			closes++
		}
	}
	if strings.HasSuffix(strings.TrimSpace(line), "&&") || strings.HasSuffix(strings.TrimSpace(line), "||") {
		// a continuation whose body is on the next line; treat the body as conditional
		opens++
	}
	return opens, closes
}

// pathEntries splits a PATH value and stats each element. Every row is first
// initialised with all fields the controls judge, defaulted (R176), then a
// branch overwrites what it learns:
//   - an element beginning with $ or ~ is an unexpanded variable, recorded
//     variable+unresolved, never is_dot (R180);
//   - an empty element, ".", or a relative path is is_dot (a
//     working-directory injection risk);
//   - an element outside the declared PATH-dir set is NOT stat'd — it is
//     unresolved+undeclared (R175), so the collector never stats an arbitrary
//     directory (the guard would otherwise reject it);
//   - a declared element is stat'd; a stat failure is unresolved.
func pathEntries(a collect.Access, raw string) []any {
	out := []any{}
	for i, el := range strings.Split(raw, ":") {
		rec := map[string]any{
			"position": i, "value": el,
			"exists": false, "unresolved": false,
			"is_dot": false, "variable": false, "undeclared": false,
			"group_writable": false, "world_writable": false,
			"mode": -1, "uid": -1, "gid": -1,
		}
		switch {
		case strings.HasPrefix(el, "$") || strings.HasPrefix(el, "~"):
			rec["variable"] = true
			rec["unresolved"] = true
			out = append(out, rec)
			continue
		case el == "" || el == "." || !strings.HasPrefix(el, "/"):
			rec["is_dot"] = true
			out = append(out, rec)
			continue
		}
		if !declared(a, el) {
			rec["unresolved"] = true
			rec["undeclared"] = true
			out = append(out, rec)
			continue
		}
		meta, err := a.Stat(el)
		if err != nil {
			rec["unresolved"] = true
			out = append(out, rec)
			continue
		}
		rec["exists"] = true
		rec["mode"] = int(meta.Mode)
		rec["uid"] = int(meta.UID)
		rec["gid"] = int(meta.GID)
		rec["group_writable"] = meta.Mode&0o020 != 0
		rec["world_writable"] = meta.Mode&0o002 != 0
		out = append(out, rec)
	}
	return out
}
