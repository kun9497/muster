// Package profile reads muster's profiles — the list of questions check asks
// a host: which controls, with which parameter values, at which severity
// (stage 3D-1, spec §3) — and merges a site's tuning in. It never touches the
// host: files come through the open function the caller passes and
// warnings through warn (Z-5).
package profile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var ErrInvalid = errors.New("invalid profile")

// SeverityEntry maps the controls a glob selects to a severity level; the
// last matching entry wins.
type SeverityEntry struct {
	Controls string `yaml:"controls" json:"controls"` // the json tags spell the digest's canonical form (Z-20)
	Level    string `yaml:"level" json:"level"`
}

// File is a profile file as decoded.
type File struct {
	Profile  string                    `yaml:"profile"`
	Extends  string                    `yaml:"extends,omitempty"`
	Include  []string                  `yaml:"include,omitempty"`
	Exclude  []string                  `yaml:"exclude,omitempty"`
	Params   map[string]map[string]any `yaml:"params,omitempty"`
	Severity []SeverityEntry           `yaml:"severity,omitempty"`
}

// Source names a built-in profile (Name) or a profile file (Path); exactly
// one is set.
type Source struct {
	Name string
	Path string
}

var nameGrammar = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// SourceOf classifies a --profile or extends value (spec §3): a value with
// no separator and no .yaml/.yml suffix is a name, anything else a path.
// The caller decides what an unknown name means (Resolve refuses it).
func SourceOf(s string) Source {
	lower := strings.ToLower(s)
	if strings.ContainsAny(s, `/\`) || strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
		return Source{Path: s}
	}
	return Source{Name: s}
}

// builtins holds the embedded profiles as Go literals; kisa-unix-2026 is an
// alias of default (Y-1).
var builtins = map[string]*File{
	"default": {Profile: "default", Include: []string{"muster.*"}},
}

var builtinAliases = map[string]string{"kisa-unix-2026": "default"}

// Builtins lists the built-in names, canonical names first, for refusals.
func Builtins() []string { return []string{"default", "kisa-unix-2026"} }

func builtin(name string) (*File, string, bool) {
	if canon, ok := builtinAliases[name]; ok {
		name = canon
	}
	f, ok := builtins[name]
	return f, name, ok
}

// Parse decodes a profile file strictly (Z-2).
func Parse(data []byte) (*File, error) {
	f, err := parse(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return f, nil
}

// parse is Parse without the sentinel; loadChain wraps once with the path so
// the YAML message survives (Z-14).
func parse(data []byte) (*File, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return nil, err
	}
	// One document per file: a second one used to be ignored without a word.
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, errors.New("more than one YAML document")
	}
	return &f, nil
}

// cleanPath is the identity of a profile file inside a chain: the path
// muster opens, cleaned (spec §3 "Names and paths").
func cleanPath(p string) string { return filepath.Clean(p) }
