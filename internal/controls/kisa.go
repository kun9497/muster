package controls

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// KISAItem is one row of the KISA Unix item inventory under
// docs/reference/kisa: the item code, its Korean name, the category and
// importance the guide assigns it, and the page it appears on. It carries no
// guide text beyond the item name (ATTRIBUTION.md); the shape is the one
// tools/coverage already reads.
type KISAItem struct {
	ID         string `json:"id"`
	NameKo     string `json:"name_ko"`
	Category   string `json:"category"`
	Importance string `json:"importance"`
	Page       int    `json:"page"`
}

// Deferral is one 2026 item muster deliberately does not enrol yet: the id,
// the stage it is planned for and muster's own reason for the delay. It is
// what lets the set-level coverage rule pass honestly -- an item is either
// implemented by exactly one control or listed here, never simply forgotten.
type Deferral struct {
	ID     string `json:"id"`
	Stage  string `json:"stage"`
	Reason string `json:"reason"`
}

// KISAInventory is what the lint cross-checks references.kisa against: the
// item lists keyed by edition year and the deferrals. "2026" is the current
// edition, held in kisa_items_latest.json.
type KISAInventory struct {
	Items    map[string][]KISAItem
	Deferred []Deferral

	byEdition map[string]map[string]KISAItem
}

// LatestKISAEdition is the edition year kisa_items_latest.json holds. It is
// the edition muster keys on, and the only one the coverage and importance
// rules judge (M-26: a 2021 id may legitimately be cited by two controls,
// because 2021 items were split and renumbered into 2026).
const LatestKISAEdition = "2026"

// kisaEditionFiles maps each edition year to its file under the inventory
// directory, in the order LoadKISA reads them.
var kisaEditionFiles = []struct{ year, file string }{
	{LatestKISAEdition, "kisa_items_latest.json"},
	{"2021", "kisa_items_2021.json"},
}

const kisaDeferredFile = "kisa_deferred.json"

// LoadKISA reads the item inventory and the deferrals from dir (normally
// docs/reference/kisa). Every item file must exist: an inventory that
// silently has nothing in it would let the cross-check pass on an empty set
// of ids, which is the one failure mode the cross-check exists to prevent.
// kisa_deferred.json is different -- an empty deferral list is a legitimate
// state (every item enrolled), so a missing file is an empty list.
func LoadKISA(dir string) (*KISAInventory, error) {
	x := &KISAInventory{Items: map[string][]KISAItem{}, byEdition: map[string]map[string]KISAItem{}}
	for _, ed := range kisaEditionFiles {
		path := filepath.Join(dir, ed.file)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("kisa inventory: %w", err)
		}
		var items []KISAItem
		if err := json.Unmarshal(data, &items); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if len(items) == 0 {
			return nil, fmt.Errorf("%s: inventory is empty", path)
		}
		byID := make(map[string]KISAItem, len(items))
		for _, it := range items {
			if it.ID == "" {
				return nil, fmt.Errorf("%s: an item has no id", path)
			}
			if _, dup := byID[it.ID]; dup {
				return nil, fmt.Errorf("%s: duplicate item %s", path, it.ID)
			}
			byID[it.ID] = it
		}
		x.Items[ed.year] = items
		x.byEdition[ed.year] = byID
	}
	data, err := os.ReadFile(filepath.Join(dir, kisaDeferredFile))
	switch {
	case os.IsNotExist(err):
		x.Deferred = nil
	case err != nil:
		return nil, fmt.Errorf("kisa inventory: %w", err)
	default:
		if err := json.Unmarshal(data, &x.Deferred); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(dir, kisaDeferredFile), err)
		}
	}
	return x, nil
}

// Item returns the item with the given id in the given edition. The second
// result is false both for an unknown id and for an edition muster holds no
// inventory file for.
func (x *KISAInventory) Item(year, id string) (KISAItem, bool) {
	it, ok := x.byEdition[year][id]
	return it, ok
}

// HasEdition reports whether the inventory holds the item list for year, so
// lint can tell "this id is wrong" from "muster cannot check this edition".
func (x *KISAInventory) HasEdition(year string) bool {
	_, ok := x.byEdition[year]
	return ok
}

// IsDeferred reports whether id is listed in kisa_deferred.json.
func (x *KISAInventory) IsDeferred(id string) bool {
	for _, d := range x.Deferred {
		if d.ID == id {
			return true
		}
	}
	return false
}
