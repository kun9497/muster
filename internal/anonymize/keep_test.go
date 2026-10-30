package anonymize

import (
	"strings"
	"testing"
)

func TestKept(t *testing.T) {
	for _, n := range []string{"root", "ftp", "lp", "uucp", "nuucp", "adm", "syslog", "utmp", "wheel", "sudo", "admin", "ALL", "*"} {
		if !Kept(n) {
			t.Errorf("%q not kept", n)
		}
	}
	for _, n := range []string{"toor", "Root", "all", "", "alice"} {
		if Kept(n) {
			t.Errorf("%q kept", n)
		}
	}
	if KeepSetVersion != "v1" {
		t.Errorf("KeepSetVersion = %q", KeepSetVersion)
	}
}

func TestClassTokens(t *testing.T) {
	want := map[string]string{ClassAccount: "account", ClassHost: "host", ClassAddress: "address", ClassURL: "url",
		ClassFingerprint: "fingerprint", ClassMachineID: "machine_id_hash", ClassPath: "path"}
	for got, w := range want {
		if got != w {
			t.Errorf("class %q != %q", got, w)
		}
	}
}

func TestLedgerRefusesCollisions(t *testing.T) {
	l := NewLedger()
	if err := l.Note("f", ClassAccount, "alice", "uaaa"); err != nil {
		t.Fatal(err)
	}
	if err := l.Note("f", ClassAccount, "alice", "uaaa"); err != nil {
		t.Errorf("repeat of one mapping: %v", err)
	}
	err := l.Note("g", ClassAccount, "bob", "uaaa")
	if err == nil || !strings.Contains(err.Error(), ClassAccount) {
		t.Errorf("two inputs to one output: %v", err)
	}
	err = l.Note("g", ClassAccount, "carol", "root")
	if err == nil || !strings.Contains(err.Error(), ClassAccount) {
		t.Errorf("output equal to a kept name: %v", err)
	}
	if err := l.Note("g", ClassKept, "root", "root"); err != nil {
		t.Errorf("a kept name maps to itself: %v", err)
	}
}

func TestKeepingWinsAcrossClasses(t *testing.T) {
	l := NewLedger()
	for i := 0; i < 2; i++ {
		if err := l.Note("users", ClassAccount, "admin", "admin"); err != nil {
			t.Fatal(err)
		}
		if err := l.Note("groups", ClassAccount, "admin", "admin"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLedgerRefusesAnotherClassesOutputInOneField(t *testing.T) {
	l := NewLedger()
	if err := l.Note("f", ClassAccount, "alice", "uxyz"); err != nil {
		t.Fatal(err)
	}
	err := l.Note("f", ClassHost, "web", "uxyz")
	if err == nil || !strings.Contains(err.Error(), ClassHost) || !strings.Contains(err.Error(), "f") {
		t.Errorf("cross-class equal output: %v", err)
	}
	if err := l.Note("other", ClassHost, "web", "uxyz"); err != nil {
		t.Errorf("different field must not collide: %v", err)
	}
}
