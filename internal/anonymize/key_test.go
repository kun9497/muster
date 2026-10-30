package anonymize

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

func testKey(t *testing.T, b byte) *Key {
	t.Helper()
	k, err := NewKey(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestNewKeyRefusesWrongLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := NewKey(make([]byte, n)); err == nil {
			t.Errorf("NewKey(%d bytes) accepted", n)
		}
	}
}

func TestKeyIDIs16Hex(t *testing.T) {
	id := testKey(t, 1).ID()
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(id) {
		t.Fatalf("ID %q", id)
	}
	if id == testKey(t, 2).ID() {
		t.Fatal("ID equal across keys")
	}
}

func TestDeterministicPerKeyAndDifferingAcrossKeys(t *testing.T) {
	a, b := testKey(t, 1), testKey(t, 2)
	if a.Account("alice") != testKey(t, 1).Account("alice") || a.Account("alice") == b.Account("alice") {
		t.Error("account determinism")
	}
	if a.Host("web.site.example.test") != testKey(t, 1).Host("web.site.example.test") || a.Host("web.site.example.test") == b.Host("web.site.example.test") {
		t.Error("host determinism")
	}
	if a.Fingerprint("SHA256:x") == b.Fingerprint("SHA256:x") {
		t.Error("fingerprint across keys")
	}
	if a.MachineIDHash("ab") == b.MachineIDHash("ab") {
		t.Error("machine id across keys")
	}
}

func TestClassesAreSeparated(t *testing.T) {
	k := testKey(t, 1)
	// The same input under two classes must not share a sub-key.
	if k.Account("web")[1:11] == k.Host("web")[1:11] {
		t.Error("account and host share a sub-key")
	}
}

func TestAccountShape(t *testing.T) {
	k := testKey(t, 1)
	re := regexp.MustCompile(`^u[a-z2-7]{12}$`)
	if got := k.Account("alice"); !re.MatchString(got) {
		t.Fatalf("Account = %q", got)
	}
	if k.Account("alice") == k.Account("Alice") {
		t.Error("account must be case-sensitive")
	}
	if k.Account("") != "" || k.Host("") != "" || k.Fingerprint("") != "" || k.MachineIDHash("") != "" {
		t.Error("empty must map to empty")
	}
}

func TestAccountSigils(t *testing.T) {
	k := testKey(t, 1)
	bare := k.Account("admins")
	for _, s := range []string{"%", "+", "-", "@"} {
		if got := k.Account(s + "admins"); got != s+bare {
			t.Errorf("%sadmins -> %q, want %q", s, got, s+bare)
		}
	}
	if got := k.Account("+@ng"); got != "+"+k.Account("@ng") || !strings.HasPrefix(got, "+@u") {
		t.Errorf("+@ng -> %q", got)
	}
	if got := k.Account("#1001"); got != "#1001" {
		t.Errorf("#1001 -> %q", got)
	}
	if got := k.Account("#x"); got != "#"+k.Account("x") {
		t.Errorf("#x -> %q", got)
	}
	if got := k.Account("%root"); got != "%root" {
		t.Errorf("%%root -> %q", got)
	}
	if k.Account("%") != "%" {
		t.Errorf("lone sigil -> %q", k.Account("%"))
	}
}

func TestAccountKeepsTheKeepSet(t *testing.T) {
	k := testKey(t, 1)
	for _, n := range []string{"root", "admin", "ALL", "*", "wheel"} {
		if k.Account(n) != n {
			t.Errorf("%s was mapped", n)
		}
	}
	if k.Account("toor") == "toor" {
		t.Error("toor kept")
	}
}

func TestHostRules(t *testing.T) {
	k := testKey(t, 1)
	lab := regexp.MustCompile(`^h[a-z2-7]{10}$`)
	got := k.Host("Web01.Site.Example.org")
	parts := strings.Split(got, ".")
	if len(parts) != 4 || parts[3] != "org" {
		t.Fatalf("Host = %q", got)
	}
	for _, p := range parts[:3] {
		if !lab.MatchString(p) {
			t.Errorf("label %q", p)
		}
	}
	if got != k.Host("web01.site.example.org") {
		t.Error("not case-folded")
	}
	// A label maps the same wherever it stands.
	if strings.Split(k.Host("web01.other.net"), ".")[0] != parts[0] {
		t.Error("label mapping not per label")
	}
	if g := k.Host("web01.site.example.org."); g != got+"." {
		t.Errorf("trailing dot: %q", g)
	}
	if g := k.Host("Solo"); !lab.MatchString(g) {
		t.Errorf("single label %q", g)
	}
	if g := k.Host("solo."); g != k.Host("solo")+"." {
		t.Errorf("single label trailing dot %q", g)
	}
}

func TestFingerprintAndMachineID(t *testing.T) {
	k := testKey(t, 1)
	if g := k.Fingerprint("SHA256:abc"); !regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`).MatchString(g) {
		t.Errorf("fingerprint %q", g)
	}
	if g := k.MachineIDHash(strings.Repeat("a", 64)); !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(g) {
		t.Errorf("machine id %q", g)
	}
}
