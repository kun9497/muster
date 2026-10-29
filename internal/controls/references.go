package controls

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/kun9497/muster/internal/cisindex"
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

	// The CIS namespace (CB-16): a name may be a STIG product and a CIS
	// product at once, so none of these maps is shared with the STIG ones.
	cisProducts map[string]string // product or alias -> product
	cisIndex    map[string]*cisindex.Index
	cisFrom     map[string]string
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
	cisFiles, err := filepath.Glob(filepath.Join(dir, "cis", "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(cisFiles)
	if err := loadCIS(x, cisFiles, os.ReadFile); err != nil {
		return nil, err
	}
	return x, nil
}

// parseCISIndex decodes one CIS index file strictly.
func parseCISIndex(data []byte) (*cisindex.Index, error) { return cisindex.DecodeIndex(data) }

// loadCIS adds the CIS index files (already sorted) to x. M-4 holds within
// the CIS family only: a product or alias two files claim is refused.
func loadCIS(x *ReferenceIndex, files []string, read func(string) ([]byte, error)) error {
	x.cisProducts = map[string]string{}
	x.cisIndex = map[string]*cisindex.Index{}
	x.cisFrom = map[string]string{}
	for _, f := range files {
		data, err := read(f)
		if err != nil {
			return err
		}
		ix, err := parseCISIndex(data)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		for _, name := range append([]string{ix.Product}, ix.AppliesTo...) {
			if prev, ok := x.cisFrom[name]; ok && prev != f {
				return fmt.Errorf("duplicate CIS index for product %s: %s and %s", name, prev, f)
			}
			x.cisFrom[name] = f
			x.cisProducts[name] = ix.Product
		}
		x.cisIndex[ix.Product] = ix
	}
	return nil
}

// HasCIS reports whether rec exists in the indexed release of the canonical
// CIS product (an alias is not resolved here).
func (x *ReferenceIndex) HasCIS(product, version, rec string) bool {
	_, ok := x.CISLevels(product, version, rec)
	return ok
}

// CISProduct resolves a product or applies_to alias to the canonical CIS
// product; alias reports that name was an alias.
func (x *ReferenceIndex) CISProduct(name string) (product string, alias bool, ok bool) {
	p, ok := x.cisProducts[name]
	if !ok {
		return "", false, false
	}
	return p, p != name, true
}

// CISLevels returns the levels of rec in the indexed release of a canonical
// CIS product.
func (x *ReferenceIndex) CISLevels(product, version, rec string) ([]string, bool) {
	ix := x.cisIndex[product]
	if ix == nil || ix.Version != version {
		return nil, false
	}
	for _, r := range ix.Recs {
		if r.Rec == rec {
			return r.Levels, true
		}
	}
	return nil, false
}

// CISRows returns a copy of the product's rows sorted by recommendation
// number; an unknown product returns nil.
func (x *ReferenceIndex) CISRows(product string) []cisindex.Row {
	ix := x.cisIndex[product]
	if ix == nil {
		return nil
	}
	rows := append([]cisindex.Row(nil), ix.Recs...)
	sort.SliceStable(rows, func(i, j int) bool { return cisindex.CompareRec(rows[i].Rec, rows[j].Rec) < 0 })
	return rows
}

// CISVersion is the indexed version of a canonical CIS product, or "".
func (x *ReferenceIndex) CISVersion(product string) string {
	if ix := x.cisIndex[product]; ix != nil {
		return ix.Version
	}
	return ""
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
