package facts

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed registry.yaml
var registryYAML []byte

// ErrUnregistered is returned by Resolve for a key no control may reference
// (spec §5.5).
var ErrUnregistered = errors.New("fact key is not registered")

// Entry describes one key a control may reference (spec §5.5).
type Entry struct {
	Key         string `yaml:"key"`
	Type        string `yaml:"type"` // string | int | bool | list<string> | record | list<record> | setting<T>
	Description string `yaml:"description"`
	Since       int    `yaml:"since"`
	Sensitivity string `yaml:"sensitivity"` // public | internal | secret
	Collector   string `yaml:"collector"`
	DefaultOn   string `yaml:"default_on,omitempty"`   // settings only: runtime | persisted | effective | both
	SubjectKind string `yaml:"subject_kind,omitempty"` // list types only: file | dir | user | group | unit | port | module | mount | key
}

// Registry is the single truth for fact keys, their types and sensitivity.
type Registry struct {
	SchemaVersion int     `yaml:"schema_version"`
	Keys          []Entry `yaml:"keys"`
	byKey         map[string]Entry
}

var validTypes = map[string]bool{"string": true, "int": true, "bool": true, "list<string>": true, "record": true, "list<record>": true}
var validSensitivity = map[string]bool{"public": true, "internal": true, "secret": true}
var validOn = map[string]bool{"runtime": true, "persisted": true, "effective": true, "both": true}
var validSubjectKind = map[string]bool{"file": true, "dir": true, "user": true, "group": true, "unit": true, "port": true, "module": true, "mount": true, "key": true}

// LoadRegistry parses the embedded registry strictly and validates it.
func LoadRegistry() (*Registry, error) {
	var r Registry
	dec := yaml.NewDecoder(bytes.NewReader(registryYAML))
	dec.KnownFields(true)
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("registry.yaml: %w", err)
	}
	r.byKey = make(map[string]Entry, len(r.Keys))
	for _, e := range r.Keys {
		if _, dup := r.byKey[e.Key]; dup {
			return nil, fmt.Errorf("registry.yaml: duplicate key %q", e.Key)
		}
		isSetting := strings.HasPrefix(e.Type, "setting<") && strings.HasSuffix(e.Type, ">")
		inner := e.Type
		if isSetting {
			inner = strings.TrimSuffix(strings.TrimPrefix(e.Type, "setting<"), ">")
		}
		if !validTypes[inner] {
			return nil, fmt.Errorf("registry.yaml: key %q has unknown type %q", e.Key, e.Type)
		}
		if !validSensitivity[e.Sensitivity] {
			return nil, fmt.Errorf("registry.yaml: key %q has unknown sensitivity %q", e.Key, e.Sensitivity)
		}
		if e.DefaultOn != "" && (!isSetting || !validOn[e.DefaultOn]) {
			return nil, fmt.Errorf("registry.yaml: key %q: default_on %q is only valid on a setting type", e.Key, e.DefaultOn)
		}
		if isSetting && e.DefaultOn == "" {
			return nil, fmt.Errorf("registry.yaml: setting key %q needs default_on", e.Key)
		}
		if e.SubjectKind != "" && (!strings.HasPrefix(e.Type, "list<") || !validSubjectKind[e.SubjectKind]) {
			return nil, fmt.Errorf("registry.yaml: key %q: subject_kind %q is only valid on a list type", e.Key, e.SubjectKind)
		}
		if e.Since < 1 {
			return nil, fmt.Errorf("registry.yaml: key %q needs since >= 1", e.Key)
		}
		r.byKey[e.Key] = e
	}
	return &r, nil
}

// Lookup returns the entry for key.
func (r *Registry) Lookup(key string) (Entry, bool) {
	e, ok := r.byKey[key]
	return e, ok
}

// IsSetting reports whether e is a two-home setting (spec §5.3).
func (r *Registry) IsSetting(e Entry) bool { return strings.HasPrefix(e.Type, "setting<") }

// Resolved is the outcome of looking a key up in a snapshot: exactly one of
// Envelope or Setting is set.
type Resolved struct {
	Entry    Entry
	Envelope *Envelope
	Setting  *Setting
}

// Resolve looks key up in s. A registered key the snapshot does not carry
// resolves to a "missing" envelope (spec §5.2); an unregistered key is an
// error, because controls may reference registered keys only (spec §5.5).
func (r *Registry) Resolve(s *Snapshot, key string) (Resolved, error) {
	e, ok := r.byKey[key]
	if !ok {
		return Resolved{}, fmt.Errorf("%w: %s", ErrUnregistered, key)
	}
	leaf, found := walk(s.Facts, strings.Split(key, "."))
	if !found {
		return Resolved{Entry: e, Envelope: Missing(key)}, nil
	}
	obj, isObj := leaf.(map[string]any)
	if !isObj {
		return Resolved{Entry: e, Envelope: &Envelope{Status: StatusError, Reason: "malformed fact: leaf is not an object"}}, nil
	}
	raw, _ := json.Marshal(obj)
	if r.IsSetting(e) {
		var st Setting
		if err := json.Unmarshal(raw, &st); err != nil || (st.Runtime == nil && st.Persisted == nil && st.Effective == nil) {
			return Resolved{Entry: e, Envelope: &Envelope{Status: StatusError, Reason: "malformed fact: setting has no sides"}}, nil
		}
		for _, side := range []*Envelope{st.Runtime, st.Persisted, st.Effective} {
			screenStatus(side)
		}
		return Resolved{Entry: e, Setting: &st}, nil
	}
	if _, hasStatus := obj["status"]; !hasStatus {
		return Resolved{Entry: e, Envelope: &Envelope{Status: StatusError, Reason: "malformed fact: no status"}}, nil
	}
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return Resolved{Entry: e, Envelope: &Envelope{Status: StatusError, Reason: "malformed fact: " + err.Error()}}, nil
	}
	screenStatus(&env)
	return Resolved{Entry: e, Envelope: &env}, nil
}

// screenStatus turns a status no collector may write — a forged value, or
// the reader-only "missing" — into an error envelope, so it can never be
// mistaken for "absent" and resolved by absent_means (spec §5.2, §6.5).
func screenStatus(env *Envelope) {
	if env == nil || env.Status.Valid() {
		return
	}
	*env = Envelope{Status: StatusError, Reason: fmt.Sprintf("malformed fact: unknown status %q", env.Status)}
}

// walk descends a decoded JSON tree by path segments. A segment that lands on
// a non-object before the last step means the key is not present.
func walk(tree map[string]any, segs []string) (any, bool) {
	var cur any = tree
	for _, seg := range segs {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}
