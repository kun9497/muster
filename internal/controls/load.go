package controls

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	controlsembed "github.com/kun9497/muster/controls"
)

// Set is one loaded control set: its version, a digest over every file, and
// the controls sorted by id (spec §6.1).
type Set struct {
	Version  string
	Digest   string
	Controls []Control
	byID     map[string]int
}

// ByID returns the control with the given id.
func (s *Set) ByID(id string) (*Control, bool) {
	i, ok := s.byID[id]
	if !ok {
		return nil, false
	}
	return &s.Controls[i], true
}

// LoadDefault loads the control set embedded in the binary (D15).
func LoadDefault() (*Set, error) { return LoadFS(controlsembed.FS) }

// LoadFS loads VERSION and every *.yaml outside testdata from fsys, decoding
// each file strictly so a misspelled key is an error, not a silent PASS
// (spec §6.8).
func LoadFS(fsys fs.FS) (*Set, error) {
	verBytes, err := fs.ReadFile(fsys, "VERSION")
	if err != nil {
		return nil, fmt.Errorf("control set has no VERSION file: %w", err)
	}
	set := &Set{Version: strings.TrimSpace(string(verBytes)), byID: map[string]int{}}
	var paths []string
	err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".yaml") {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk control set: %w", err)
	}
	sort.Strings(paths)
	h := sha256.New()
	h.Write(verBytes)
	for _, p := range paths {
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil, err
		}
		h.Write([]byte(p + "\n"))
		h.Write(data)
		var c Control
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&c); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if c.ID == "" {
			return nil, fmt.Errorf("%s: control has no id", p)
		}
		c.Path = path.Clean(p)
		set.Controls = append(set.Controls, c)
	}
	sort.Slice(set.Controls, func(i, j int) bool { return set.Controls[i].ID < set.Controls[j].ID })
	for i, c := range set.Controls {
		if _, dup := set.byID[c.ID]; dup {
			return nil, fmt.Errorf("%s: duplicate control id %q", c.Path, c.ID)
		}
		set.byID[c.ID] = i
	}
	set.Digest = "sha256:" + hex.EncodeToString(h.Sum(nil))
	return set, nil
}
