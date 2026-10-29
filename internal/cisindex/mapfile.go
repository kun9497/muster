package cisindex

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"

	"gopkg.in/yaml.v3"
)

// RecRow is a recommendation a control reaches without a rule id (CB-5).
type RecRow struct {
	Rec    string `yaml:"rec"`
	Reason string `yaml:"reason"`
}

// VarRow names a ComplianceAsCode variable, the muster parameter it sets and
// the conversion (CB-8). As is the string "int" or a map[string]any table
// from the selected text to a value; Param "none" carries a Reason instead.
type VarRow struct {
	Var    string `yaml:"var"`
	Param  string `yaml:"param"`
	As     any    `yaml:"as,omitempty"`
	Reason string `yaml:"reason,omitempty"`
}

// MapRow is one control's row of map.yaml: the rule ids its clauses check,
// its variable rows and, per benchmark product, the recommendations it
// reaches through recs: alone.
type MapRow struct {
	ID    string              `yaml:"id"`
	Rules []string            `yaml:"rules"`
	Vars  []VarRow            `yaml:"vars,omitempty"`
	Recs  map[string][]RecRow `yaml:"recs,omitempty"`
}

// ReviewRow takes a candidate control out of one profile (CB-7, CB-8).
type ReviewRow struct {
	Profile string `yaml:"profile"`
	ID      string `yaml:"id"`
	Reason  string `yaml:"reason"`
}

// decodeOne decodes exactly one YAML document strictly into out.
func decodeOne(what string, data []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		if err == io.EOF {
			return fmt.Errorf("%s: no YAML document", what)
		}
		return fmt.Errorf("%s: %w", what, err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("%s: more than one YAML document", what)
	}
	return nil
}

// DecodeMap reads map.yaml strictly: one document, rows sorted by id with no
// duplicate, every vars: row well formed and every reason non-empty.
func DecodeMap(data []byte) ([]MapRow, error) {
	var rows []MapRow
	if err := decodeOne("map", data, &rows); err != nil {
		return nil, err
	}
	for i, r := range rows {
		if r.ID == "" {
			return nil, fmt.Errorf("map: row %d has no id", i)
		}
		if i > 0 && rows[i-1].ID >= r.ID {
			if rows[i-1].ID == r.ID {
				return nil, fmt.Errorf("map: %s appears twice", r.ID)
			}
			return nil, fmt.Errorf("map: %s is not sorted after %s", r.ID, rows[i-1].ID)
		}
		vars := map[string]bool{}
		for _, v := range r.Vars {
			if err := checkVarRow(v); err != nil {
				return nil, fmt.Errorf("map: %s: %w", r.ID, err)
			}
			if vars[v.Var] {
				return nil, fmt.Errorf("map: %s: variable %s is named twice", r.ID, v.Var)
			}
			vars[v.Var] = true
		}
		products := make([]string, 0, len(r.Recs))
		for product := range r.Recs {
			products = append(products, product)
		}
		sort.Strings(products)
		for _, product := range products {
			recs := r.Recs[product]
			if product == "" {
				return nil, fmt.Errorf("map: %s: recs: with no product", r.ID)
			}
			for _, rr := range recs {
				if rr.Rec == "" || rr.Reason == "" {
					return nil, fmt.Errorf("map: %s: recs: %s: a row needs a rec and a reason", r.ID, product)
				}
			}
		}
	}
	return rows, nil
}

// checkVarRow is the shape of a vars: row: a variable name, a parameter, and
// either param none with a reason or a conversion with none.
func checkVarRow(v VarRow) error {
	if !ValidRuleID(v.Var) {
		return fmt.Errorf("vars: variable %q is not a variable name", v.Var)
	}
	if v.Param == "" {
		return fmt.Errorf("vars: %s has no param", v.Var)
	}
	if v.Param == "none" {
		if v.Reason == "" {
			return fmt.Errorf("vars: %s: param none needs a reason", v.Var)
		}
		if v.As != nil {
			return fmt.Errorf("vars: %s: param none takes no as", v.Var)
		}
		return nil
	}
	if v.Reason != "" {
		return fmt.Errorf("vars: %s: a reason belongs to param none only", v.Var)
	}
	switch as := v.As.(type) {
	case nil:
		return fmt.Errorf("vars: %s: param %s needs an as", v.Var, v.Param)
	case string:
		if as != "int" {
			return fmt.Errorf("vars: %s: as %q is neither int nor a table", v.Var, as)
		}
	case map[string]any:
		if len(as) == 0 {
			return fmt.Errorf("vars: %s: the as table is empty", v.Var)
		}
	case map[any]any:
		return fmt.Errorf("vars: %s: every as table key must be a string (quote it)", v.Var)
	default:
		return fmt.Errorf("vars: %s: as %v is neither int nor a table", v.Var, v.As)
	}
	return nil
}

// DecodeReview reads review.yaml strictly: one document, rows unique by
// {profile, id}, every field non-empty.
func DecodeReview(data []byte) ([]ReviewRow, error) {
	var rows []ReviewRow
	if err := decodeOne("review", data, &rows); err != nil {
		return nil, err
	}
	seen := map[[2]string]bool{}
	for i, r := range rows {
		if r.Profile == "" || r.ID == "" || r.Reason == "" {
			return nil, fmt.Errorf("review: row %d needs a profile, an id and a reason", i)
		}
		k := [2]string{r.Profile, r.ID}
		if seen[k] {
			return nil, fmt.Errorf("review: %s on %s appears twice", r.ID, r.Profile)
		}
		seen[k] = true
	}
	return rows, nil
}

// CheckReviewProfiles refuses a review row whose profile is not one of the
// generated profiles' names.
func CheckReviewProfiles(review []ReviewRow, profiles []string) error {
	known := map[string]bool{}
	for _, p := range profiles {
		known[p] = true
	}
	var errs []error
	for _, r := range review {
		if !known[r.Profile] {
			errs = append(errs, fmt.Errorf("review: %s names profile %s, which is not generated", r.ID, r.Profile))
		}
	}
	return errors.Join(errs...)
}
