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

// writeKISADir copies the committed inventory into a temp directory,
// replacing the named files with the given bodies. An empty body leaves the
// file out entirely.
func writeKISADir(t *testing.T, replace map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"kisa_items_latest.json", "kisa_items_2021.json", "kisa_deferred.json"} {
		body, replaced := replace[name]
		if !replaced {
			data, err := os.ReadFile(filepath.Join(repoKISA, name))
			if err != nil {
				t.Fatal(err)
			}
			body = string(data)
		}
		if body == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// M-37: kisa_deferred.json is the only sanctioned way to make the coverage
// gate pass while an item is unimplemented, so an entry that says nothing --
// no id, no stage, no reason -- is a hole in the gate, not a row. That is a
// property of the file, so it is caught at the file.
func TestLoadKISARejectsAnIncompleteDeferral(t *testing.T) {
	cases := map[string]string{
		"no id":     `[{"id": "", "stage": "3", "reason": "r"}]`,
		"no stage":  `[{"id": "U-15", "stage": "", "reason": "r"}]`,
		"no reason": `[{"id": "U-15", "stage": "3", "reason": "   "}]`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := writeKISADir(t, map[string]string{"kisa_deferred.json": body})
			_, err := LoadKISA(dir)
			if err == nil {
				t.Fatal("an incomplete deferral must be an error")
			}
			for _, want := range []string{"kisa_deferred.json", "deferral 0"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q must name %q", err, want)
				}
			}
		})
	}
	if _, err := LoadKISA(writeKISADir(t, nil)); err != nil {
		t.Errorf("the committed deferral list must load: %v", err)
	}
}

// LOW 5: a broken importance in the inventory used to surface as a
// kisa_importance problem blaming the control for the file.
func TestLoadKISARejectsAnItemWithAnUnknownImportance(t *testing.T) {
	body := `[{"id": "U-01", "name_ko": "n", "category": "c", "importance": "high", "page": 1}]`
	_, err := LoadKISA(writeKISADir(t, map[string]string{"kisa_items_latest.json": body}))
	if err == nil {
		t.Fatal("an importance outside 상/중/하 must be an error")
	}
	for _, want := range []string{"kisa_items_latest.json", "U-01", "high"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q must name %q", err, want)
		}
	}
}

// LOW 12: every message names the file the same way, including the read.
func TestLoadKISANamesTheFileOnAReadFailure(t *testing.T) {
	dir := writeKISADir(t, map[string]string{"kisa_items_2021.json": ""})
	_, err := LoadKISA(dir)
	if err == nil {
		t.Fatal("a missing edition file must be an error")
	}
	want := filepath.Join(dir, "kisa_items_2021.json")
	if !strings.HasPrefix(err.Error(), want+": ") {
		t.Errorf("error %q must start with %q, the way the decode errors do", err, want+": ")
	}
}
