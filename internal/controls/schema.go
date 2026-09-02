// Package controls defines the control YAML schema (spec §6), loads sets
// strictly and lints them.
package controls

import (
	"bytes"
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"
)

// Clause is one judgment (spec §6.3). Under checks/when/applies_when it names
// a fact; under where/require it names a field of the element being examined
// (or neither, for a scalar element).
type Clause struct {
	Fact     string  `yaml:"fact,omitempty"`
	Field    string  `yaml:"field,omitempty"`
	Op       string  `yaml:"op"`
	Expected any     `yaml:"expected,omitempty"`
	On       string  `yaml:"on,omitempty"`
	Persona  string  `yaml:"persona,omitempty"`
	Subject  string  `yaml:"subject,omitempty"`
	Where    *Clause `yaml:"where,omitempty"`
	Require  *Clause `yaml:"require,omitempty"`
}

// ClauseList accepts either one mapping (shorthand for a one-element list)
// or a sequence of mappings (spec §6.3).
type ClauseList []Clause

func (l *ClauseList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.MappingNode:
		var c Clause
		if err := decodeStrict(n, &c); err != nil {
			return err
		}
		*l = ClauseList{c}
		return nil
	case yaml.SequenceNode:
		var cs []Clause
		if err := decodeStrict(n, &cs); err != nil {
			return err
		}
		*l = ClauseList(cs)
		return nil
	default:
		return fmt.Errorf("line %d: clause list must be a mapping or a sequence", n.Line)
	}
}

// decodeStrict decodes n into out with KnownFields(true). Node.Decode always
// builds a decoder with knownFields false, which would let an unknown key
// anywhere under applies_when or mechanisms[].when pass silently (spec §6.8),
// so we re-encode the node and run it back through a fresh strict decoder
// instead of calling n.Decode directly.
func decodeStrict(n *yaml.Node, out any) error {
	data, err := yaml.Marshal(n)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	return dec.Decode(out)
}

type Mechanism struct {
	When   ClauseList `yaml:"when"`
	Checks []Clause   `yaml:"checks"`
}

type Param struct {
	Type        string `yaml:"type"`
	Default     any    `yaml:"default"`
	Description string `yaml:"description"`
}

type CISRef struct {
	Benchmark string `yaml:"benchmark"`
	Version   string `yaml:"version"`
	Rec       string `yaml:"rec"`
}

type References struct {
	KISA      map[string][]string `yaml:"kisa,omitempty"`
	CIS       []CISRef            `yaml:"cis,omitempty"`
	ISMSP     []string            `yaml:"isms_p,omitempty"`
	NIST80053 []string            `yaml:"nist_800_53,omitempty"`
}

type Remediation struct {
	TextEn     string `yaml:"text_en"`
	TextKo     string `yaml:"text_ko"`
	Risk       string `yaml:"risk"` // none | restart_service | reboot_required | lockout_risk
	Idempotent bool   `yaml:"idempotent"`
	Script     string `yaml:"script,omitempty"`
	Rollback   string `yaml:"rollback,omitempty"`
}

// Control is one YAML file (spec §6.2).
type Control struct {
	ID            string           `yaml:"id"`
	TitleEn       string           `yaml:"title_en"`
	TitleKo       string           `yaml:"title_ko"`
	DescriptionEn string           `yaml:"description_en"`
	DescriptionKo string           `yaml:"description_ko"`
	Category      string           `yaml:"category"`   // account | file | service | patch | log | beyond
	Importance    string           `yaml:"importance"` // 상 | 중 | 하
	Automation    string           `yaml:"automation"` // auto | partial | manual | not_applicable
	ManualReason  string           `yaml:"manual_reason,omitempty"`
	References    References       `yaml:"references"`
	RequiresFacts string           `yaml:"requires_facts"`
	AppliesWhen   ClauseList       `yaml:"applies_when,omitempty"`
	AbsentMeans   string           `yaml:"absent_means,omitempty"` // pass | fail | not_applicable | manual
	Params        map[string]Param `yaml:"params,omitempty"`
	Checks        []Clause         `yaml:"checks,omitempty"`
	Mechanisms    []Mechanism      `yaml:"mechanisms,omitempty"`
	Custom        string           `yaml:"custom,omitempty"`
	Remediation   *Remediation     `yaml:"remediation,omitempty"`
	Decision      string           `yaml:"decision,omitempty"`

	Path string `yaml:"-"` // relative path inside the set, filled by the loader
}

// SortedParamNames returns parameter names in a fixed order so nothing that
// walks Params can leak map order into output (spec §9, D20).
func (c *Control) SortedParamNames() []string {
	names := make([]string, 0, len(c.Params))
	for n := range c.Params {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
