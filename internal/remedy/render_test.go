package remedy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from the golden; run go test ./internal/remedy -run 'TestTableGolden|TestJSONGolden' -update and review the diff\n%s", path, got)
	}
}

func TestTableGolden(t *testing.T) {
	for _, g := range []struct {
		name string
		mk   func(*testing.T) *Plan
	}{{"full", fullPlan}, {"empty", emptyPlan}, {"poison", poisonPlan}} {
		t.Run(g.name, func(t *testing.T) { golden(t, g.name+".table", Table(g.mk(t), false)) })
	}
}

func TestJSONGolden(t *testing.T) {
	for _, g := range []struct {
		name string
		mk   func(*testing.T) *Plan
	}{{"full", fullPlan}, {"empty", emptyPlan}} {
		t.Run(g.name, func(t *testing.T) { golden(t, g.name+".json", JSON(g.mk(t))) })
	}
}

// TestTablePoisoned: host, profile, titles, reasons and texts all carry ESC,
// BEL and newlines; the uncoloured table carries none of them raw, and no
// injected newline adds a line.
func TestTablePoisoned(t *testing.T) {
	p := poisonPlan(t)
	out := Table(p, false)
	if i := bytes.IndexByte(out, 0x1b); i >= 0 {
		t.Fatalf("poisoned table carries a raw ESC at %d:\n%q", i, out)
	}
	if bytes.IndexByte(out, 0x07) >= 0 {
		t.Fatalf("poisoned table carries a raw BEL:\n%q", out)
	}
	// four header lines, a blank, the column header, three lines per item
	if got, want := len(lines(out)), 6+3*len(p.Items); got != want {
		t.Fatalf("poisoned table has %d lines, want %d: an injected newline split one\n%s", got, want, out)
	}
}

// itemLine is the table row of the item with this id.
func itemLine(t *testing.T, out []byte, id string) string {
	t.Helper()
	for _, l := range lines(out) {
		if strings.Contains(l, "  "+id+" ") {
			return l
		}
	}
	t.Fatalf("no row for %s in\n%s", id, out)
	return ""
}

// TestTableColorPaintsRiskAndStatus pins report.Paint and report.StatusColor
// through the fix table (no other test exercises colour output).
func TestTableColorPaintsRiskAndStatus(t *testing.T) {
	out := Table(fullPlan(t), true)
	lock := itemLine(t, out, "muster.test.c_lockout")
	if !strings.Contains(lock, "  \x1b[31mlockout_risk   \x1b[0m  ") {
		t.Fatalf("lockout risk cell is not painted red: %q", lock)
	}
	if !strings.Contains(lock, "  \x1b[31mfail  \x1b[0m  ") {
		t.Fatalf("FAIL status cell is not painted red: %q", lock)
	}
	none := itemLine(t, out, "muster.test.a_none")
	if !strings.Contains(none, "  none             muster.test.a_none") {
		t.Fatalf("none risk cell is not plain: %q", none)
	}
	if strings.Count(none, "\x1b[") != 2 { // the status cell's open and reset only
		t.Fatalf("none row carries escapes beyond its status cell: %q", none)
	}
	warn := itemLine(t, out, "muster.test.f_partial")
	if !strings.Contains(warn, "  \x1b[33mwarn  \x1b[0m  ") {
		t.Fatalf("WARN status cell is not painted yellow: %q", warn)
	}
	if bytes.IndexByte(Table(fullPlan(t), false), 0x1b) >= 0 {
		t.Fatal("color=false painted")
	}
}

func TestJSONEmptyListsAreArrays(t *testing.T) {
	empty := string(JSON(emptyPlan(t)))
	for _, want := range []string{`"items": []`, `"not_planned": []`} {
		if !strings.Contains(empty, want) {
			t.Fatalf("empty plan JSON lacks %s:\n%s", want, empty)
		}
	}
	var doc struct {
		Items []map[string]json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(JSON(fullPlan(t)), &doc); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range doc.Items {
		if string(it["id"]) == `"muster.test.d_reboot"` {
			found = true
			if string(it["backup"]) != "[]" {
				t.Fatalf("text-only item backup = %s, want []", it["backup"])
			}
		}
	}
	if !found {
		t.Fatal("no text-only item muster.test.d_reboot")
	}
}

func TestTableEmptyPlan(t *testing.T) {
	ls := lines(Table(emptyPlan(t), false))
	if len(ls) != 6 || ls[4] != "" || ls[5] != "nothing to fix" {
		t.Fatalf("empty table = %q, want four header lines, a blank and nothing to fix", ls)
	}
	if !strings.HasPrefix(ls[0], "muster ") || !strings.HasPrefix(ls[1], "fix --dry-run · profile default") ||
		!strings.HasPrefix(ls[2], "planned 0 ") || !strings.HasPrefix(ls[3], "by risk: ") {
		t.Fatalf("empty table header = %q", ls[:4])
	}
}

func TestTableNotPlannedOnlyWhenNonEmpty(t *testing.T) {
	full := string(Table(fullPlan(t), false))
	if !strings.Contains(full, "\nnot planned:\n") {
		t.Fatalf("full table lacks the not-planned section:\n%s", full)
	}
	for _, id := range []string{"x.degraded", "x.error", "x.manual"} {
		if !strings.Contains(full, "\n  "+id+" ") {
			t.Fatalf("not-planned section lacks %s:\n%s", id, full)
		}
	}
	capped := string(Table(cappedPlan(t), false))
	if strings.Contains(capped, "\nnot planned:\n") { // the summary line says "not planned: error 0, …"
		t.Fatalf("a plan with no not-planned rows prints the section:\n%s", capped)
	}
	if !strings.Contains(capped, " (above max-risk)") {
		t.Fatalf("capped table does not mark items above max-risk:\n%s", capped)
	}
}
