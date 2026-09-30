package collectors

import (
	"reflect"
	"testing"
)

// V-6: glibc's loader blanks every '#' through the end of its line and
// splits what is left on space, tab, newline and ':'.
func TestParseLdSoPreload(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want []string
	}{
		{"sample", readSeed(t, "ld.so.preload.sample"), []string{"/usr/lib/libfoo.so", "/usr/lib/libbar.so", "/opt/x.so"}},
		{"comment mid-line", []byte("a #b\nc"), []string{"a", "c"}},
		{"empty", []byte(""), []string{}},
		{"only comments and separators", []byte("# x\n \t::\n#y"), []string{}},
		{"hash inside a token", []byte("/lib/a.so#tail b\n/lib/c.so"), []string{"/lib/a.so", "/lib/c.so"}},
		{"tab and final token without separator", []byte("x\ty:z"), []string{"x", "y", "z"}},
		// '\r' is not one of glibc's separators: a CRLF file loads "a\r".
		{"carriage return kept", []byte("a\r\nb"), []string{"a\r", "b"}},
	}
	for _, c := range cases {
		got := parseLdSoPreload(c.in)
		if got == nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: parseLdSoPreload(%q) = %#v, want %#v", c.name, c.in, got, c.want)
		}
	}
}
