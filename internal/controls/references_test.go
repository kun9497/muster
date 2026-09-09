package controls

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadReferenceIndexResolvesProductsAliasesAndNIST(t *testing.T) {
	x, err := LoadReferenceIndex("testdata/refs")
	if err != nil {
		t.Fatal(err)
	}
	if !x.HasSTIG("mini", "V1R1", "MINI-00-000010") {
		t.Error("indexed id must resolve")
	}
	if !x.HasSTIG("mini-clone", "V1R1", "MINI-00-000020") {
		t.Error("an applies_to alias must resolve to its product")
	}
	for _, bad := range [][3]string{{"mini", "V1R2", "MINI-00-000010"}, {"mini", "V1R1", "MINI-00-999999"}, {"other", "V1R1", "MINI-00-000010"}} {
		if x.HasSTIG(bad[0], bad[1], bad[2]) {
			t.Errorf("%v must not resolve", bad)
		}
	}
	if !x.HasNIST("AC-17(2)") || !x.HasNIST("CM-6") || x.HasNIST("AC-99") {
		t.Error("NIST union is wrong")
	}
}

func TestLoadReferenceIndexRejectsAMissingDirectory(t *testing.T) {
	if _, err := LoadReferenceIndex("testdata/does-not-exist"); err == nil {
		t.Error("a missing stig directory must be an error, never an empty index")
	}
}

// R97/ruling: the strict YAML decoder that guards every control field must
// also reject an unknown key nested under references.stig, the same way it
// already rejects one under references.cis.
func TestStrictLoaderRejectsUnknownKeyInSTIGReference(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte("t+1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "account"), 0o755); err != nil {
		t.Fatal(err)
	}
	bad := `id: muster.account.bad_stig
title_en: t
title_ko: t
category: account
importance: 상
automation: auto
absent_means: fail
references:
  stig: [{ benchmark: x, version: y, id: z, extra: 1 }]
checks: [{ fact: services.ssh.installed, op: eq, expected: true }]
remediation: { text_en: t, text_ko: t, risk: none }
`
	if err := os.WriteFile(filepath.Join(dir, "account", "bad.yaml"), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFS(os.DirFS(dir)); err == nil || !strings.Contains(err.Error(), "extra") {
		t.Fatalf("err=%v, want a strict-decoding error naming the unknown key", err)
	}
}

// M-4: two index files claiming the same product would let the later one
// silently shadow the earlier, so lint would accept ids from one release and
// reject ids from the other with no explanation. The same is true of an
// applies_to alias that collides with another file's product.
func TestLoadReferenceIndexRejectsADuplicateProduct(t *testing.T) {
	const rules = `, "version": "V1R1", "rules": [{"stig_id": "DUP-00-000010", "nist": ["CM-6"]}]}`
	write := func(t *testing.T, dir, name, body string) string {
		t.Helper()
		p := filepath.Join(dir, "stig", name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	newDir := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "stig"), 0o755); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	dir := newDir(t)
	a := write(t, dir, "a-rhel9.json", `{"product": "rhel9"`+rules)
	b := write(t, dir, "b-rhel9.json", `{"product": "rhel9"`+rules)
	_, err := LoadReferenceIndex(dir)
	if err == nil {
		t.Fatal("two files for one product must be an error")
	}
	for _, want := range []string{"rhel9", filepath.Base(a), filepath.Base(b)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q must name %q", err, want)
		}
	}

	dir = newDir(t)
	write(t, dir, "a-rhel9.json", `{"product": "rhel9"`+rules)
	write(t, dir, "b-rocky9.json", `{"product": "rocky9", "applies_to": ["rhel9"]`+rules)
	if _, err := LoadReferenceIndex(dir); err == nil {
		t.Error("an applies_to alias colliding with another file's product must be an error")
	}

	// A file that lists its own product as an alias is not a collision.
	dir = newDir(t)
	write(t, dir, "a-rhel9.json", `{"product": "rhel9", "applies_to": ["rhel9", "alma9"]`+rules)
	x, err := LoadReferenceIndex(dir)
	if err != nil {
		t.Fatalf("a self-alias must load: %v", err)
	}
	if !x.HasSTIG("alma9", "V1R1", "DUP-00-000010") {
		t.Error("the alias must still resolve")
	}
}

// M-4: the index remembers where it came from, so lint can name that
// directory instead of the literal docs/reference/stig.
func TestLoadReferenceIndexRecordsItsDirectory(t *testing.T) {
	dir := filepath.Join("testdata", "refs")
	x, err := LoadReferenceIndex(dir)
	if err != nil {
		t.Fatal(err)
	}
	if x.Dir != dir {
		t.Errorf("Dir = %q, want %q", x.Dir, dir)
	}
}
