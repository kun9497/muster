package controls

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func cisDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	st, err := os.ReadFile("testdata/refs/stig/mini-v1r1.json")
	if err != nil {
		t.Fatal(err)
	}
	for rel, body := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "stig"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stig", "mini-v1r1.json"), st, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func cisDoc(product, alias string) string {
	return `{"product":"` + product + `","benchmark":"B","version":"1.0.0","applies_to":[` + alias + `],"source":{"repo":"r","tag":"t","commit":"c","path":"p","sha256":"s"},"counts":{"l1_server":0},"recs":[{"rec":"1.1","levels":[],"controls":[],"rules":"none"}]}`
}

func TestLoadCISIndexAlongsideSTIG(t *testing.T) {
	x, err := LoadReferenceIndex("testdata/refs")
	if err != nil {
		t.Fatal(err)
	}
	if !x.HasCIS("mini", "1.0.0", "1.1.1") {
		t.Error("HasCIS(mini,1.0.0,1.1.1) must be true")
	}
	if x.HasCIS("mini", "2.0.0", "1.1.1") {
		t.Error("a wrong version must be false")
	}
	if x.HasCIS("minialias", "1.0.0", "1.1.1") {
		t.Error("HasCIS takes the canonical product only")
	}
	p, alias, ok := x.CISProduct("minialias")
	if p != "mini" || !alias || !ok {
		t.Errorf("CISProduct(minialias) = %q %v %v", p, alias, ok)
	}
	if p, alias, ok := x.CISProduct("mini"); p != "mini" || alias || !ok {
		t.Errorf("CISProduct(mini) = %q %v %v", p, alias, ok)
	}
	if _, _, ok := x.CISProduct("nope"); ok {
		t.Error("unknown product must not be ok")
	}
	lv, ok := x.CISLevels("mini", "1.0.0", "1.1.1")
	if !ok || !reflect.DeepEqual(lv, []string{"l1_server"}) {
		t.Errorf("CISLevels = %v %v", lv, ok)
	}
	if _, ok := x.CISLevels("mini", "1.0.0", "9.9"); ok {
		t.Error("unknown rec must not be ok")
	}
	rows := x.CISRows("mini")
	if len(rows) != 2 || rows[0].Rec != "1.1.1" || rows[1].Rec != "2.1" || rows[1].Rules != "some" {
		t.Errorf("CISRows = %+v", rows)
	}
	if x.CISRows("nope") != nil {
		t.Error("unknown product rows must be nil")
	}
	if x.CISVersion("mini") != "1.0.0" || x.CISVersion("nope") != "" {
		t.Error("CISVersion")
	}
	// The STIG side is untouched by the CIS file.
	if !x.HasSTIG("mini", "V1R1", "MINI-00-000010") {
		t.Error("STIG index must still load")
	}
}

func TestLoadWithoutCISDir(t *testing.T) {
	x, err := LoadReferenceIndex(cisDir(t, nil))
	if err != nil {
		t.Fatalf("no cis/ dir must not be an error: %v", err)
	}
	if x.HasCIS("mini", "1.0.0", "1.1.1") || x.CISRows("mini") != nil {
		t.Error("nothing is indexed without cis/")
	}
}

func TestCISDuplicateProductRefused(t *testing.T) {
	dir := cisDir(t, map[string]string{
		"cis/a.json": cisDoc("dup", ""),
		"cis/b.json": cisDoc("dup", ""),
	})
	_, err := LoadReferenceIndex(dir)
	if err == nil {
		t.Fatal("two CIS files for one product must be an error")
	}
	for _, want := range []string{"dup", "a.json", "b.json"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q must name %q", err, want)
		}
	}
	dir = cisDir(t, map[string]string{
		"cis/a.json": cisDoc("one", ""),
		"cis/b.json": cisDoc("two", `"one"`),
	})
	if _, err := LoadReferenceIndex(dir); err == nil {
		t.Error("an alias colliding with another CIS product must be an error")
	}
}

func TestCISIndexStrict(t *testing.T) {
	body := strings.Replace(cisDoc("strict", ""), `"benchmark"`, `"title":"x","benchmark"`, 1)
	_, err := LoadReferenceIndex(cisDir(t, map[string]string{"cis/strict.json": body}))
	if err == nil || !strings.Contains(err.Error(), "strict.json") || !strings.Contains(err.Error(), "title") {
		t.Fatalf("err=%v, want a strict-decoding error naming the file and key", err)
	}
}

func TestSTIGAndCISShareProductName(t *testing.T) {
	dir := cisDir(t, map[string]string{"cis/u.json": cisDoc("mini", `"mini-clone"`)})
	x, err := LoadReferenceIndex(dir)
	if err != nil {
		t.Fatalf("a CIS product beside a STIG product of the same name must load: %v", err)
	}
	if !x.HasSTIG("mini", "V1R1", "MINI-00-000010") || !x.HasCIS("mini", "1.0.0", "1.1") {
		t.Error("both namespaces must answer")
	}
}
