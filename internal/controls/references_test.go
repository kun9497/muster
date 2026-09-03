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
