package controls

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// repoKISA is the committed inventory, relative to this package.
var repoKISA = filepath.Join("..", "..", "docs", "reference", "kisa")

func mustLoadKISA(t *testing.T) *KISAInventory {
	t.Helper()
	x, err := LoadKISA(repoKISA)
	if err != nil {
		t.Fatalf("LoadKISA(%s): %v", repoKISA, err)
	}
	return x
}

// M-2: the cross-check needs the whole inventory -- the 2026 edition
// (kisa_items_latest.json), the 2021 edition a control may still cite, and
// the deferrals that let the coverage rule pass honestly while an item is
// unimplemented.
func TestLoadKISAReadsTheInventoryAndDeferrals(t *testing.T) {
	x := mustLoadKISA(t)

	if got := len(x.Items["2026"]); got != 67 {
		t.Errorf("2026 edition has %d items, want 67", got)
	}
	if got := len(x.Items["2021"]); got != 72 {
		t.Errorf("2021 edition has %d items, want 72", got)
	}
	if _, ok := x.Items["1999"]; ok {
		t.Error("an edition with no inventory file must be absent from Items")
	}

	it, ok := x.Item("2026", "U-01")
	if !ok {
		t.Fatal("U-01 must be in the 2026 edition")
	}
	if it.ID != "U-01" || it.Importance != "상" || it.NameKo == "" || it.Category == "" || it.Page == 0 {
		t.Errorf("U-01 decoded as %+v; every field of the row must survive the decode", it)
	}
	if _, ok := x.Item("2026", "U-99"); ok {
		t.Error("U-99 is in no edition and must not resolve")
	}
	if _, ok := x.Item("1999", "U-01"); ok {
		t.Error("an edition with no inventory file must resolve nothing")
	}
	// The two editions are separate lists, not one merged set: 2021 renumbered
	// into 2026, so it has ids 2026 does not.
	if _, ok := x.Item("2021", "U-72"); !ok {
		t.Error("U-72 must be in the 2021 edition")
	}
	if _, ok := x.Item("2026", "U-72"); ok {
		t.Error("U-72 must not be in the 2026 edition; the editions must not be merged")
	}

	if len(x.Deferred) != 3 {
		t.Fatalf("deferrals = %+v, want three", x.Deferred)
	}
	var ids []string
	for _, d := range x.Deferred {
		ids = append(ids, d.ID)
		if d.Stage == "" || d.Reason == "" {
			t.Errorf("deferral %+v needs a stage and a reason", d)
		}
		if _, ok := x.Item("2026", d.ID); !ok {
			t.Errorf("deferral %s names an id that is not a 2026 item", d.ID)
		}
	}
	sort.Strings(ids)
	want := []string{"U-15", "U-23", "U-33"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("deferred ids = %v, want %v", ids, want)
	}
}

// The item files are the inventory: without them the cross-check would pass
// on an empty set of ids, so a missing one is an error naming the file. The
// deferral list is different -- an empty one is a legitimate state (every
// item enrolled), so a missing file is an empty list.
func TestLoadKISAMissingFiles(t *testing.T) {
	_, err := LoadKISA(t.TempDir())
	if err == nil {
		t.Fatal("a directory with no inventory must be an error, never an empty inventory")
	}
	if !strings.Contains(err.Error(), "kisa_items_latest.json") {
		t.Errorf("error %q must name the missing file", err)
	}

	dir := t.TempDir()
	for _, name := range []string{"kisa_items_latest.json", "kisa_items_2021.json"} {
		data, err := os.ReadFile(filepath.Join(repoKISA, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	x, err := LoadKISA(dir)
	if err != nil {
		t.Fatalf("a missing kisa_deferred.json must not be an error: %v", err)
	}
	if len(x.Deferred) != 0 {
		t.Errorf("deferrals = %+v, want none", x.Deferred)
	}
	if len(x.Items["2026"]) != 67 {
		t.Errorf("the 2026 edition must still load: %d items", len(x.Items["2026"]))
	}
}
