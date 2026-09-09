package controls

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

// ReferenceIndex is what tools/refindex generated under docs/reference/stig:
// which STIG ids exist per product and release, and the NIST 800-53 ids
// they map to. Lint accepts only identifiers found here (spec §3).
type ReferenceIndex struct {
	// Dir is the directory LoadReferenceIndex was given, so a message about
	// an unindexed id can name the index the reader actually passed rather
	// than the literal docs/reference/stig (M-4).
	Dir string

	products map[string]string          // product or alias -> product
	versions map[string]string          // product -> indexed version
	stig     map[string]map[string]bool // product -> id set
	nist     map[string]bool
	from     map[string]string // product or alias -> the file that claimed it
}

var (
	nistIDRe = regexp.MustCompile(`^[A-Z]{2}-\d+(\(\d+\))?$`)
	stigIDRe = regexp.MustCompile(`^[A-Z0-9]+-[0-9]+-[0-9]+$`)
)

// LoadReferenceIndex reads every dir/stig/*.json. A missing directory or an
// empty one is an error: an index that silently has nothing in it would let
// no reference through, and lint would blame every control.
func LoadReferenceIndex(dir string) (*ReferenceIndex, error) {
	files, err := filepath.Glob(filepath.Join(dir, "stig", "*.json"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("reference index: no stig/*.json under %s (run: go run ./tools/refindex)", dir)
	}
	sort.Strings(files)
	x := &ReferenceIndex{Dir: dir, products: map[string]string{}, versions: map[string]string{}, stig: map[string]map[string]bool{}, nist: map[string]bool{}, from: map[string]string{}}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var doc struct {
			Product   string   `json:"product"`
			AppliesTo []string `json:"applies_to"`
			Version   string   `json:"version"`
			Rules     []struct {
				StigID string   `json:"stig_id"`
				NIST   []string `json:"nist"`
			} `json:"rules"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if doc.Product == "" || doc.Version == "" {
			return nil, fmt.Errorf("%s: product and version are required", f)
		}
		// M-4: two files claiming one product (or an applies_to alias that
		// collides with another file's product) would let the later file
		// silently shadow the earlier, so lint would accept ids from one
		// release and reject ids from the other with nothing to explain it.
		// Files are walked in sorted order, so the message is stable.
		for _, name := range append([]string{doc.Product}, doc.AppliesTo...) {
			if prev, ok := x.from[name]; ok && prev != f {
				return nil, fmt.Errorf("duplicate index for product %s: %s and %s", name, prev, f)
			}
			x.from[name] = f
			x.products[name] = doc.Product
		}
		x.versions[doc.Product] = doc.Version
		ids := map[string]bool{}
		for _, r := range doc.Rules {
			ids[r.StigID] = true
			for _, n := range r.NIST {
				x.nist[n] = true
			}
		}
		x.stig[doc.Product] = ids
	}
	return x, nil
}

// HasSTIG reports whether id exists in the indexed release of benchmark (a
// product name or an applies_to alias).
func (x *ReferenceIndex) HasSTIG(benchmark, version, id string) bool {
	p, ok := x.products[benchmark]
	if !ok || x.versions[p] != version {
		return false
	}
	return x.stig[p][id]
}

// HasNIST reports whether id appears in any indexed rule's NIST mapping.
func (x *ReferenceIndex) HasNIST(id string) bool { return x.nist[id] }

// ValidNISTID is the format check that runs even without an index.
func ValidNISTID(id string) bool { return nistIDRe.MatchString(id) }

// ValidSTIGID is the format check that runs even without an index.
func ValidSTIGID(id string) bool { return stigIDRe.MatchString(id) }
