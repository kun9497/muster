package collectors

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestMachineIDHashRefusesMalformedIDs(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"
	sum := sha256.Sum256([]byte(id))
	want := hex.EncodeToString(sum[:])
	for _, c := range []struct {
		name, in, want string
	}{
		{"plain", id, want},
		{"trailing LF", id + "\n", want},
		{"CRLF", id + "\r\n", want},
		{"leading blanks", "  \t" + id, want},
		{"leading LF", "\n" + id, want},
		{"uninitialized", "uninitialized\n", ""},
		{"uppercase", "0123456789ABCDEF0123456789ABCDEF", ""},
		{"31 chars", id[:31], ""},
		{"33 chars", id + "0", ""},
		{"interior space", id[:16] + " " + id[16:], ""},
		{"whitespace only", " \n\t", ""},
		{"empty", "", ""},
		{"VT and FF", "\v" + id + "\f", want},
		{"wrapped in U+00A0", " " + id + " ", ""},
		{"followed by U+0085", id + "\u0085", ""},
	} {
		if got := MachineIDHash([]byte(c.in)); got != c.want {
			t.Errorf("%s: MachineIDHash(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}
