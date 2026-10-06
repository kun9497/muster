package pkgindex

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// One fuzz target per byte parser of the package (CLAUDE.md, W-37). Each
// asserts what a parser must hold whatever it is fed: it does not panic (the
// fuzzer's own rule), it answers the same twice on the same input, and it
// never returns more rows than the input has bytes. The seeds are the
// collectors' package-database fixtures, which the walk's join tests read.
//
// The file has no build tag: the parsers are untagged, so the seed corpus
// runs on any host with `go test ./...`.

const seedDir = "../collect/collectors/testdata"

func seeds(f *testing.F, globs ...string) {
	f.Helper()
	for _, g := range globs {
		names, err := filepath.Glob(filepath.Join(seedDir, g))
		if err != nil || len(names) == 0 {
			f.Fatalf("seed glob %s names no file (%v)", g, err)
		}
		for _, n := range names {
			data, err := os.ReadFile(n)
			if err != nil {
				f.Fatalf("seed %s: %v", n, err)
			}
			f.Add(data)
		}
	}
}

// fuzzBody runs a parser twice and checks determinism and the row bound.
func fuzzBody(t *testing.T, name string, run func() (any, int), inputLen int) {
	t.Helper()
	first, rows := run()
	second, _ := run()
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("%s is not deterministic on the same input", name)
	}
	if rows > inputLen+1 {
		t.Fatalf("%s returned %d rows from %d input bytes", name, rows, inputLen)
	}
}

var fuzzCands = map[string]bool{"/usr/bin/su": true, "/usr/bin/at": true, "/usr/bin/passwd": true}

func FuzzRPMFileTable(f *testing.F) {
	seeds(f, "rpm.qa-files.*", "rpm_files_caps.sample")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "RPMFileTable", func() (any, int) {
			whole, errWhole := RPMFileTable(data, fuzzCands, false)
			cut, errCut := RPMFileTable(data, fuzzCands, true)
			if len(cut) > len(whole) && errWhole == nil {
				t.Fatalf("a capped read held %d rows, the whole read %d", len(cut), len(whole))
			}
			return []any{whole, errWhole != nil, cut, errCut != nil}, len(whole)
		}, len(data))
	})
}

func FuzzParseDpkgStatus(f *testing.F) {
	seeds(f, "dpkg.status*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "ParseDpkgStatus", func() (any, int) {
			out := ParseDpkgStatus(data)
			for _, p := range out {
				if p.Name == "" {
					t.Fatal("an installed package without a name")
				}
			}
			return out, len(out)
		}, len(data))
	})
}

func FuzzDpkgListPaths(f *testing.F) {
	seeds(f, "dpkg.info/*.list*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "dpkgListPaths", func() (any, int) {
			out := dpkgListPaths(data)
			for _, p := range out {
				if p == "" {
					t.Fatal("an empty path")
				}
			}
			return out, len(out)
		}, len(data))
	})
}

func FuzzParseDiversions(f *testing.F) {
	seeds(f, "dpkg.diversions.sample")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseDiversions", func() (any, int) {
			out := parseDiversions(data, map[string]string{"/bin": "/usr/bin", "/sbin": "/usr/sbin"})
			for _, d := range out {
				if d.from == "" || d.to == "" || d.from == d.to {
					t.Fatalf("a diversion that diverts nothing: %+v", d)
				}
			}
			return out, len(out)
		}, len(data))
	})
}

func FuzzParseStatOverrides(f *testing.F) {
	seeds(f, "dpkg.statoverride.sample")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseStatOverrides", func() (any, int) {
			out := parseStatOverrides(data, map[string]string{"/bin": "/usr/bin"})
			for _, l := range out {
				if l.ov.Mode&^0o7777 != 0 {
					t.Fatalf("mode %o outside 0o7777", l.ov.Mode)
				}
			}
			return out, len(out)
		}, len(data))
	})
}
