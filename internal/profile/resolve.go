package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"sort"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/tuning"
)

// Resolved is a profile resolved against a control set.
type Resolved struct {
	Name         string
	Source       string
	Chain        []string
	IDs          []string
	Params       map[string]map[string]any
	Severity     []SeverityEntry
	SeverityByID map[string]string
	Digest       string
}

const maxChain = 4

var levels = map[string]bool{"high": true, "medium": true, "low": true}

// link is one file of the chain in walk order (root first).
type link struct {
	file  *File
	label string // "builtin:default" or "file:<cleaned path>"
	where string // the string refusals name: the path, or "builtin:<name>"
}

// Resolve walks the extends chain root-first and applies include/exclude,
// params and severity per file (spec §3). open reads a file by path; warn
// receives the severity warning. Every refusal wraps ErrInvalid and names
// the file.
func Resolve(set *controls.Set, src Source, open func(string) ([]byte, error), warn func(string)) (*Resolved, error) {
	chain, err := loadChain(src, open)
	if err != nil {
		return nil, err
	}
	selected := map[string]bool{}
	r := &Resolved{Params: map[string]map[string]any{}, SeverityByID: map[string]string{}}
	for _, l := range chain {
		r.Chain = append(r.Chain, l.label)
		for _, p := range l.file.Include {
			ids, err := match(set, p, l.where)
			if err != nil {
				return nil, err
			}
			for _, id := range ids {
				selected[id] = true
			}
		}
		for _, p := range l.file.Exclude {
			ids, err := match(set, p, l.where)
			if err != nil {
				return nil, err
			}
			for _, id := range ids {
				delete(selected, id)
			}
		}
		if err := tuning.Validate(set, l.file.Params); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, l.where, err)
		}
		for id, ps := range l.file.Params {
			if r.Params[id] == nil {
				r.Params[id] = map[string]any{}
			}
			for n, v := range ps {
				r.Params[id][n] = v
			}
		}
		for _, e := range l.file.Severity {
			if !levels[e.Level] {
				return nil, fmt.Errorf("%w: %s: severity level %q is not high, medium or low", ErrInvalid, l.where, e.Level)
			}
			if _, err := match(set, e.Controls, l.where); err != nil {
				return nil, err
			}
			r.Severity = append(r.Severity, e)
		}
	}
	for id := range selected {
		r.IDs = append(r.IDs, id)
	}
	sort.Strings(r.IDs)
	if len(r.IDs) == 0 {
		return nil, fmt.Errorf("%w: %s: profile selects no control", ErrInvalid, chain[len(chain)-1].where)
	}
	for _, e := range r.Severity {
		hit := false
		for _, id := range r.IDs {
			if ok, _ := path.Match(e.Controls, id); ok {
				r.SeverityByID[id] = e.Level
				hit = true
			}
		}
		if !hit {
			warn(fmt.Sprintf("severity entry %s matches only excluded controls", e.Controls))
		}
	}
	last := chain[len(chain)-1]
	r.Name = last.file.Profile
	r.Source = "builtin"
	if src.Path != "" {
		r.Source = "file:" + src.Path
	}
	r.Digest = digest(r)
	return r, nil
}

// loadChain follows extends from src to the root and returns the chain root
// first: at most four files, the built-in counted, identified by cleaned
// paths for the cycle test.
func loadChain(src Source, open func(string) ([]byte, error)) ([]link, error) {
	var chain []link // leaf first, reversed at the end
	seen := map[string]bool{}
	cur := src
	referrer := ""
	for {
		var l link
		if cur.Name != "" {
			f, canon, ok := builtin(cur.Name)
			if !ok {
				if referrer != "" {
					return nil, fmt.Errorf("%w: %s: extends %s: unknown profile; the built-ins are %s", ErrInvalid, referrer, cur.Name, joinNames())
				}
				return nil, fmt.Errorf("%w: unknown profile %q; the built-ins are %s", ErrInvalid, cur.Name, joinNames())
			}
			l = link{file: f, label: "builtin:" + canon, where: "builtin:" + canon}
		} else {
			p := cur.Path
			if referrer != "" && !filepath.IsAbs(p) {
				p = filepath.Join(filepath.Dir(referrer), p)
			}
			p = cleanPath(p)
			// The cycle identity is the cleaned opened path, never the label
			// (the flag's file is labelled as given): ./a.yaml and a.yaml are
			// one file.
			if seen["file:"+p] {
				return nil, fmt.Errorf("%w: %s: extends %s closes a cycle through %s", ErrInvalid, referrer, cur.Path, p)
			}
			seen["file:"+p] = true
			data, err := open(p)
			if err != nil {
				if referrer != "" {
					return nil, fmt.Errorf("%w: %s: extends %s: %v", ErrInvalid, referrer, cur.Path, err)
				}
				return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, p, err)
			}
			f, err := parse(data)
			if err != nil {
				return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, p, err)
			}
			if f.Profile == "" {
				return nil, fmt.Errorf("%w: %s: profile name is required", ErrInvalid, p)
			}
			if !nameGrammar.MatchString(f.Profile) {
				return nil, fmt.Errorf("%w: %s: profile name %q is not [a-z0-9][a-z0-9-]*", ErrInvalid, p, f.Profile)
			}
			if _, _, isBuiltin := builtin(f.Profile); isBuiltin {
				return nil, fmt.Errorf("%w: %s: profile name %q is a built-in's", ErrInvalid, p, f.Profile)
			}
			label := "file:" + p
			if referrer == "" {
				label = "file:" + src.Path // the flag's path as given
			}
			l = link{file: f, label: label, where: p}
			referrer = p
		}
		if cur.Name != "" {
			seen[l.label] = true // a built-in is its own identity
		}
		chain = append(chain, l)
		if len(chain) > maxChain {
			return nil, fmt.Errorf("%w: %s: extends chain is longer than four files", ErrInvalid, chain[0].where)
		}
		if l.file.Extends == "" || cur.Name != "" {
			break
		}
		cur = SourceOf(l.file.Extends)
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain, nil
}

// match returns the ids of the set a pattern selects; a malformed pattern or
// one that matches nothing refuses (spec §3 "Globs").
func match(set *controls.Set, pattern, where string) ([]string, error) {
	if _, err := path.Match(pattern, ""); err != nil {
		return nil, fmt.Errorf("%w: %s: pattern %q: %v", ErrInvalid, where, pattern, err)
	}
	var ids []string
	for _, c := range set.Controls {
		if ok, _ := path.Match(pattern, c.ID); ok {
			ids = append(ids, c.ID)
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("%w: %s: pattern %q matches no control", ErrInvalid, where, pattern)
	}
	return ids, nil
}

func joinNames() string {
	out := ""
	for i, n := range Builtins() {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}

// digest is sha256 over the canonical JSON of the resolved content only —
// ids, the chain's values and the ordered severity entries — never the name,
// source or chain (spec §3 "Digest"). encoding/json sorts map keys.
func digest(r *Resolved) string {
	doc := struct {
		IDs      []string                  `json:"ids"`
		Params   map[string]map[string]any `json:"params"`
		Severity []SeverityEntry           `json:"severity"`
	}{IDs: r.IDs, Params: r.Params, Severity: r.Severity}
	b, err := json.Marshal(doc)
	if err != nil {
		panic(err) // the shapes are yaml scalars and lists; marshalling cannot fail
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
