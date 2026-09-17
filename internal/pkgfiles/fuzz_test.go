package pkgfiles

import (
	"reflect"
	"testing"
)

// One fuzz target per exported parser (spec §3, F-5). Each asserts the three
// properties a parser must have whatever it is fed: it does not panic (the
// fuzzer's own rule), it answers the same twice on the same line, and nothing
// it returns is longer than the line it was given plus a small constant.
//
// The seeds are literal lines rather than files: this package takes ONE line
// with its terminator already removed, so a fixture file would only ever be
// read a line at a time anyway, and the shapes that matter — the refusals —
// are clearer written out.

// lineSlack is how much longer than its input a parser's output may be.
// CanonicalUsr rewrites "/bin/su" into "/usr/bin/su", which is four bytes
// longer than the path it was handed; nothing else grows at all.
const lineSlack = 64

// usrMerged is the alias table CanonicalUsr is fuzzed with: the six
// merged-usr symlinks a Debian or EL host ships.
func usrMerged() map[string]string {
	return map[string]string{
		"/bin":    "/usr/bin",
		"/sbin":   "/usr/sbin",
		"/lib":    "/usr/lib",
		"/lib32":  "/usr/lib32",
		"/lib64":  "/usr/lib64",
		"/libx32": "/usr/libx32",
	}
}

// fuzzBody runs one parser twice and checks determinism and the output bound.
func fuzzBody(t *testing.T, name string, run func() []any, inputLen int) {
	t.Helper()
	first, second := run(), run()
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("%s is not deterministic: %#v then %#v on the same line", name, first, second)
	}
	for i, v := range first {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if len(s) > inputLen+lineSlack {
			t.Fatalf("%s returned a %d-byte string as result %d from a %d-byte line (bound %d)",
				name, len(s), i, inputLen, inputLen+lineSlack)
		}
	}
}

func FuzzParseRPMFileLine(f *testing.F) {
	f.Add("bash\t0100755\troot\troot\t/usr/bin/bash")
	f.Add("at\t0104755\troot\troot\t/usr/bin/at")
	f.Add("coreutils\t0102755\troot\troot\t/usr/bin/a file with spaces")
	f.Add("shadow-utils\tnotoctal\troot\troot\t/usr/bin/su")
	f.Add("\t0100755\troot\troot\t/usr/bin/bash")
	f.Add("bash\t0100755\troot\troot\trelative/path")
	f.Add("")
	f.Fuzz(func(t *testing.T, line string) {
		fuzzBody(t, "ParseRPMFileLine", func() []any {
			pkg, mode, owner, group, p, ok := ParseRPMFileLine(line)
			return []any{pkg, mode, owner, group, p, ok}
		}, len(line))
	})
}

func FuzzParseTarTV(f *testing.F) {
	f.Add("-rwsr-xr-x root/root  72712 2024-01-01 00:00 ./usr/bin/at")
	f.Add("-rwxr-sr-x root/shadow  40makes 2024-01-01 00:00 ./usr/bin/chage")
	f.Add("lrwxrwxrwx root/root  0 2024-01-01 00:00 ./bin/sh -> dash")
	f.Add("hrwxrwxrwx root/root  0 2024-01-01 00:00 ./bin/hard")
	f.Add("drwxr-xr-x root/root  0 2024-01-01 00:00 ./usr/bin/")
	f.Add("-rwsr-xr-x rootroot  0 2024-01-01 00:00 ./usr/bin/at")
	f.Add("-rws root/root")
	f.Add("")
	f.Fuzz(func(t *testing.T, line string) {
		fuzzBody(t, "ParseTarTV", func() []any {
			mode, owner, group, p, ok := ParseTarTV(line)
			return []any{mode, owner, group, p, ok}
		}, len(line))
	})
}

func FuzzParseStatLine(f *testing.F) {
	f.Add("4755 root root /usr/bin/su")
	f.Add("2755 root shadow /usr/bin/chage")
	f.Add("644 root root /etc/passwd")
	f.Add("755 root root relative/path")
	f.Add("99999999999999999999 root root /usr/bin/su")
	f.Add("4755 root root /usr/bin/a file with spaces")
	f.Add("")
	f.Fuzz(func(t *testing.T, line string) {
		fuzzBody(t, "ParseStatLine", func() []any {
			mode, owner, group, p, ok := ParseStatLine(line)
			return []any{mode, owner, group, p, ok}
		}, len(line))
	})
}

func FuzzCanonicalUsr(f *testing.F) {
	f.Add("/bin/su")
	f.Add("/usr/bin/su")
	f.Add("/lib64/ld-linux-x86-64.so.2")
	f.Add("/libx32/libc.so.6")
	f.Add("/binx/other")
	f.Add("/bin")
	f.Add("")
	f.Fuzz(func(t *testing.T, p string) {
		fuzzBody(t, "CanonicalUsr", func() []any {
			return []any{CanonicalUsr(p, usrMerged())}
		}, len(p))
	})
}
