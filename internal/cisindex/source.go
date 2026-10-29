// Package cisindex decodes the pinned ComplianceAsCode control files into
// the bare facts muster keeps (recommendation numbers, levels, rule ids) and
// defines the generated CIS index. It imports no host package and no other
// muster package (3D-1b CB-2).
package cisindex

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	recRE  = regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,4}$`)
	ruleRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
)

// ValidRec reports whether s is a recommendation number such as 5.1.7.
func ValidRec(s string) bool { return recRE.MatchString(s) }

// ValidRuleID reports whether s is a ComplianceAsCode rule id.
func ValidRuleID(s string) bool { return ruleRE.MatchString(s) }

// CompareRec compares two valid recommendation numbers component-wise as
// integers; a number that is a prefix of the other sorts first.
func CompareRec(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, y := strings.TrimLeft(as[i], "0"), strings.TrimLeft(bs[i], "0")
		if len(x) != len(y) {
			if len(x) < len(y) {
				return -1
			}
			return 1
		}
		if c := strings.Compare(x, y); c != 0 {
			return c
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return 0
}

// Selection is a `var=value` element of a control's rules list.
type Selection struct{ Var, Value string }

// Entry is one recommendation of a control file: nothing but its number, its
// levels and the rules and variable selections it names.
type Entry struct {
	ID         string
	Levels     []string
	Rules      []string
	Selections []Selection
}

// Source is a decoded control file.
type Source struct {
	Version string
	Entries []Entry
}

type rawFile struct {
	Version  string `yaml:"version"`
	Controls []struct {
		ID     string   `yaml:"id"`
		Levels []string `yaml:"levels"`
		Rules  []string `yaml:"rules"`
	} `yaml:"controls"`
}

// DecodeControls reads a ComplianceAsCode control file. Every field but
// version and controls[].{id,levels,rules} is dropped by the typed decode
// (CB-2); helper entries whose id is not a recommendation number are dropped.
func DecodeControls(data []byte) (*Source, error) {
	var raw rawFile
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("control file: %w", err)
	}
	if raw.Version == "" {
		return nil, fmt.Errorf("control file: no version")
	}
	src := &Source{Version: raw.Version}
	ids := map[string]bool{}
	for i, c := range raw.Controls {
		if c.ID == "" {
			return nil, fmt.Errorf("control file: entry %d has no id", i)
		}
		if !ValidRec(c.ID) {
			continue
		}
		if ids[c.ID] {
			return nil, fmt.Errorf("control file: entry %s appears twice", c.ID)
		}
		ids[c.ID] = true
		e := Entry{ID: c.ID, Levels: c.Levels}
		seen := map[string]bool{}
		for _, r := range c.Rules {
			if v, val, ok := strings.Cut(r, "="); ok {
				if !ValidRuleID(v) {
					return nil, fmt.Errorf("control %s: rule element %q: variable %q is not a variable name", c.ID, r, v)
				}
				if val == "" {
					return nil, fmt.Errorf("control %s: rule element %q selects no value", c.ID, r)
				}
				e.Selections = append(e.Selections, Selection{Var: v, Value: val})
				continue
			}
			if !ValidRuleID(r) {
				return nil, fmt.Errorf("control %s: rule element %q is not a rule id", c.ID, r)
			}
			if !seen[r] {
				seen[r] = true
				e.Rules = append(e.Rules, r)
			}
		}
		src.Entries = append(src.Entries, e)
	}
	return src, nil
}

// HasLevel reports whether e carries level.
func HasLevel(e Entry, level string) bool {
	for _, l := range e.Levels {
		if l == level {
			return true
		}
	}
	return false
}

// RuleUnion is the set of rule ids named by any entry of the sources.
func RuleUnion(srcs ...*Source) map[string]bool {
	u := map[string]bool{}
	for _, s := range srcs {
		for _, e := range s.Entries {
			for _, r := range e.Rules {
				u[r] = true
			}
		}
	}
	return u
}

// SameIDsAndLevels returns nil when a and b hold the same entry ids with the
// same levels, in order, whatever their rules; else it names the first
// difference.
func SameIDsAndLevels(a, b *Source) error {
	for i := 0; i < len(a.Entries) || i < len(b.Entries); i++ {
		switch {
		case i >= len(a.Entries):
			return fmt.Errorf("id %s is only in the second source", b.Entries[i].ID)
		case i >= len(b.Entries):
			return fmt.Errorf("id %s is only in the first source", a.Entries[i].ID)
		case a.Entries[i].ID != b.Entries[i].ID:
			return fmt.Errorf("id %s differs from %s at entry %d", a.Entries[i].ID, b.Entries[i].ID, i)
		case strings.Join(a.Entries[i].Levels, ",") != strings.Join(b.Entries[i].Levels, ","):
			return fmt.Errorf("id %s: levels %v differ from %v", a.Entries[i].ID, a.Entries[i].Levels, b.Entries[i].Levels)
		}
	}
	return nil
}
