package profile

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// builtinFS holds the built-in profiles as strict YAML: default.yaml and the
// three CIS profiles tools/cisindex generates (spec §4). Embedding reads no
// host file, so the package still imports no os (Z-5).
//
//go:embed builtin/*.yaml
var builtinFS embed.FS

// builtins are the embedded files by canonical name, decoded once.
var builtins = mustLoadBuiltins()

func mustLoadBuiltins() map[string]*File {
	files, err := loadBuiltins()
	if err != nil {
		panic(err) // the files are part of the binary; TestEmbeddedBuiltinsLoadStrictly holds them
	}
	return files
}

// loadBuiltins decodes every embedded file with the strict parser; a file
// is named by its base name, which must be the profile it declares, and a
// built-in is a chain root (no extends).
func loadBuiltins() (map[string]*File, error) {
	paths, err := fs.Glob(builtinFS, "builtin/*.yaml")
	if err != nil {
		return nil, err
	}
	out := map[string]*File{}
	for _, p := range paths {
		data, err := builtinFS.ReadFile(p)
		if err != nil {
			return nil, err
		}
		f, err := parse(data)
		if err != nil {
			return nil, fmt.Errorf("%w: builtin %s: %v", ErrInvalid, p, err)
		}
		name := strings.TrimSuffix(path.Base(p), ".yaml")
		if f.Profile != name {
			return nil, fmt.Errorf("%w: builtin %s declares profile %q", ErrInvalid, p, f.Profile)
		}
		if f.Extends != "" {
			return nil, fmt.Errorf("%w: builtin %s extends %q", ErrInvalid, p, f.Extends)
		}
		out[name] = f
	}
	return out, nil
}

// Builtins lists the built-in names for refusals and usage: default first,
// then the other embedded profiles sorted, then the aliases sorted.
func Builtins() []string {
	var rest, aliases []string
	for n := range builtins {
		if n != "default" {
			rest = append(rest, n)
		}
	}
	for a := range builtinAliases {
		aliases = append(aliases, a)
	}
	sort.Strings(rest)
	sort.Strings(aliases)
	return append(append([]string{"default"}, rest...), aliases...)
}

// Builtin returns a copy of a built-in profile file (an alias resolved), for
// the tests that hold the generated profiles to the CIS index.
func Builtin(name string) (*File, bool) {
	f, _, ok := builtin(name)
	if !ok {
		return nil, false
	}
	c := *f
	c.Include = append([]string(nil), f.Include...)
	c.Exclude = append([]string(nil), f.Exclude...)
	c.Severity = append([]SeverityEntry(nil), f.Severity...)
	c.Params = map[string]map[string]any{}
	for id, ps := range f.Params {
		c.Params[id] = map[string]any{}
		for k, v := range ps {
			c.Params[id][k] = v
		}
	}
	return &c, true
}
