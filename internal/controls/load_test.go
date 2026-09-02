package controls

import (
	"os"
	"strings"
	"testing"
)

func TestLoadFSDecodesEveryField(t *testing.T) {
	set, err := LoadFS(os.DirFS("testdata/valid"))
	if err != nil {
		t.Fatal(err)
	}
	if set.Version != "test-set+2026.09.02" || !strings.HasPrefix(set.Digest, "sha256:") {
		t.Fatalf("version %q digest %q", set.Version, set.Digest)
	}
	c, ok := set.ByID("muster.account.example")
	if !ok {
		t.Fatal("control not loaded")
	}
	if c.Importance != "상" || c.Automation != "auto" || c.References.KISA["2026"][0] != "U-01" || c.References.CIS[0].Rec != "5.1.20" {
		t.Errorf("scalar fields: %+v", c)
	}
	if len(c.AppliesWhen) != 1 || c.AppliesWhen[0].Fact != "services.ssh.installed" {
		t.Errorf("applies_when single mapping must become a one-element list: %+v", c.AppliesWhen)
	}
	if len(c.Mechanisms) != 2 || len(c.Mechanisms[0].When) != 1 || len(c.Mechanisms[1].When) != 1 {
		t.Errorf("mechanisms: %+v", c.Mechanisms)
	}
	if c.Mechanisms[0].Checks[0].Persona != "root" || c.Mechanisms[0].Checks[0].Expected != "${allowed}" {
		t.Errorf("clause modifiers: %+v", c.Mechanisms[0].Checks[0])
	}
	if c.Mechanisms[1].Checks[0].Where == nil || c.Mechanisms[1].Checks[0].Where.Op != "matches" {
		t.Errorf("where sub-clause: %+v", c.Mechanisms[1].Checks[0])
	}
	if c.Params["allowed"].Type != "list<string>" || c.Remediation == nil || !c.Remediation.Idempotent || c.Remediation.Risk != "lockout_risk" {
		t.Errorf("params/remediation: %+v %+v", c.Params, c.Remediation)
	}
	if c.Path != "account/example.yaml" {
		t.Errorf("path %q", c.Path)
	}
}

func TestLoadFSRejectsUnknownKeys(t *testing.T) {
	_, err := LoadFS(os.DirFS("testdata/unknown_key"))
	if err == nil || !strings.Contains(err.Error(), "expcted") || !strings.Contains(err.Error(), "account/bad.yaml") {
		t.Fatalf("err=%v, want a strict-decoding error naming the key and file", err)
	}
}

func TestLoadFSRejectsUnknownKeyInAppliesWhen(t *testing.T) {
	_, err := LoadFS(os.DirFS("testdata/unknown_key_applies_when"))
	if err == nil || !strings.Contains(err.Error(), "bogus_key") || !strings.Contains(err.Error(), "account/bad.yaml") {
		t.Fatalf("err=%v, want a strict-decoding error naming the key and file", err)
	}
}

func TestLoadFSRejectsUnknownKeyInMechanismWhen(t *testing.T) {
	_, err := LoadFS(os.DirFS("testdata/unknown_key_mechanism_when"))
	if err == nil || !strings.Contains(err.Error(), "bogus_key") || !strings.Contains(err.Error(), "account/bad.yaml") {
		t.Fatalf("err=%v, want a strict-decoding error naming the key and file", err)
	}
}

func TestLoadDefaultEmbeddedSet(t *testing.T) {
	set, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if set.Version == "" || len(set.Controls) == 0 {
		t.Fatalf("embedded set: version %q, %d controls", set.Version, len(set.Controls))
	}
	for i := 1; i < len(set.Controls); i++ {
		if set.Controls[i-1].ID >= set.Controls[i].ID {
			t.Fatalf("controls not sorted by id: %q before %q", set.Controls[i-1].ID, set.Controls[i].ID)
		}
	}
}
