package anonymize

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

func FuzzHost(f *testing.F) {
	for _, s := range []string{"", "a", "web.corp.test", "WEB.Corp.", "..", ".a.", "a..b", "xn--bcher-kva.example"} {
		f.Add(s)
	}
	k, _ := NewKey(bytes.Repeat([]byte{7}, 32))
	f.Fuzz(func(t *testing.T, s string) {
		got := k.Host(s)
		if got != k.Host(s) {
			t.Fatal("not deterministic")
		}
		if s == "" && got != "" {
			t.Fatal("empty")
		}
		if strings.HasSuffix(s, ".") != strings.HasSuffix(got, ".") {
			t.Fatalf("trailing dot: %q -> %q", s, got)
		}
		if got != strings.ToLower(got) {
			t.Fatalf("upper case in %q", got)
		}
		if Kept(s) && got != s {
			t.Fatalf("kept name changed: %q -> %q", s, got)
		}
	})
}

var accountOut = regexp.MustCompile(`^[%+\-@#]*(u[a-z2-7]{12}|[0-9]*)$`)

func FuzzAccount(f *testing.F) {
	for _, s := range []string{"", "root", "%admins", "+@ng", "#1001", "#x", "-n", "@", "#", "ALL", "*"} {
		f.Add(s)
	}
	k, _ := NewKey(bytes.Repeat([]byte{7}, 32))
	f.Fuzz(func(t *testing.T, s string) {
		got := k.Account(s)
		if got != k.Account(s) {
			t.Fatal("not deterministic")
		}
		if got != s && !accountOut.MatchString(got) {
			t.Fatalf("shape: %q -> %q", s, got)
		}
		if s == "" && got != "" {
			t.Fatal("empty")
		}
	})
}
