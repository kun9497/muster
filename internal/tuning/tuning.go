// Package tuning reads one site's parameter values for muster's controls
// (stage 3D-1, spec §4): exact control ids, strictly typed, applied after the
// profile by profile.Merge. The package never touches the host: files come
// through the open function the caller passes (Z-5).
package tuning

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/kun9497/muster/internal/controls"
)

var ErrInvalid = errors.New("invalid tuning file")

// File is the tuning file as decoded.
type File struct {
	Params map[string]map[string]any `yaml:"params"`
}

// Tuning is a validated tuning file.
type Tuning struct {
	Params map[string]map[string]any
	Path   string
	Digest string
}

// Parse decodes a tuning file strictly (Z-2). An empty file is a File with
// no params.
func Parse(data []byte) (*File, error) {
	f, err := parse(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return f, nil
}

// parse is Parse without the sentinel, so Load can wrap once with the path
// and the YAML message (the unknown key, the syntax error) survives (Z-14).
func parse(data []byte) (*File, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return nil, err
	}
	return &f, nil
}

// Load reads path through open, parses it and validates every entry against
// the control set: an unknown control, an unknown parameter or a value of the
// wrong shape refuses the file naming the path. The digest is sha256 of the
// bytes, as the waiver file's is.
func Load(set *controls.Set, path string, open func(string) ([]byte, error)) (*Tuning, error) {
	data, err := open(path)
	if err != nil {
		return nil, err
	}
	f, err := parse(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, path, err)
	}
	if err := Validate(set, f.Params); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, path, err)
	}
	sum := sha256.Sum256(data)
	return &Tuning{Params: f.Params, Path: path, Digest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

// Validate checks a params map against the set: ids must exist, parameters
// must be declared, values must have the declared type (shared with the
// profile loader, which validates its params the same way).
func Validate(set *controls.Set, params map[string]map[string]any) error {
	ids := make([]string, 0, len(params))
	for id := range params {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		c, ok := set.ByID(id)
		if !ok {
			return fmt.Errorf("params name unknown control %s", id) // neutral: the profile loader shares this (Z-19)
		}
		names := make([]string, 0, len(params[id]))
		for n := range params[id] {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			p, declared := c.Params[n]
			if !declared {
				return fmt.Errorf("control %s has no parameter %s", id, n)
			}
			if err := controls.CheckParamValue(p.Type, params[id][n]); err != nil {
				return fmt.Errorf("%s.%s: %v", id, n, err)
			}
		}
	}
	return nil
}
