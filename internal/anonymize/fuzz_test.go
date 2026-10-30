package anonymize

import (
	"bytes"
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
	})
}

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
		if s == "" && got != "" {
			t.Fatal("empty")
		}
	})
}
