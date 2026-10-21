package facts

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const minimalSnapshot = `{
  "schema_version": 1,
  "run": {"muster_version": "0.1.0", "collected_at": "2026-09-02T06:00:00Z",
          "host": {"hostname": "web-01", "os_release": {"id": "rocky", "version_id": "9.4", "family": "rhel"}},
          "euid": 0, "env": {"container": "none", "has_systemd": true}, "complete": true},
  "facts": {"services": {"ssh": {"installed": {"status": "ok", "value": true}}}}
}`

func TestLoadMinimalSnapshot(t *testing.T) {
	s, err := Load(strings.NewReader(minimalSnapshot))
	if err != nil {
		t.Fatal(err)
	}
	if s.SchemaVersion != 1 || s.Run.Host.Hostname != "web-01" || !s.Run.Complete {
		t.Errorf("decoded badly: %+v", s.Run)
	}
	if _, ok := s.Facts["services"]; !ok {
		t.Errorf("facts tree lost: %v", s.Facts)
	}
}

func TestLoadRefusesHigherSchemaVersion(t *testing.T) {
	_, err := Load(strings.NewReader(`{"schema_version": 99, "run": {}, "facts": {}}`))
	if !errors.Is(err, ErrSchemaMismatch) {
		t.Fatalf("err=%v, want ErrSchemaMismatch", err)
	}
}

func TestLoadRefusesZeroOrMissingSchemaVersion(t *testing.T) {
	for _, in := range []string{`{"run": {}, "facts": {}}`, `{"schema_version": 0, "run": {}, "facts": {}}`} {
		if _, err := Load(strings.NewReader(in)); !errors.Is(err, ErrSchemaMismatch) {
			t.Errorf("%s: err=%v, want ErrSchemaMismatch", in, err)
		}
	}
}

func TestLoadRefusesOversizedInput(t *testing.T) {
	big := `{"schema_version":1,"run":{},"facts":{"pad":"` + strings.Repeat("x", MaxSnapshotBytes) + `"}}`
	if _, err := Load(strings.NewReader(big)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err=%v, want ErrTooLarge", err)
	}
}

func TestLoadRefusesDeepNesting(t *testing.T) {
	deep := `{"schema_version":1,"run":{},"facts":` + strings.Repeat(`{"a":`, MaxDepth+2) + `1` + strings.Repeat(`}`, MaxDepth+2) + `}`
	if _, err := Load(strings.NewReader(deep)); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("err=%v, want ErrTooDeep", err)
	}
}

func TestLoadRejectsMalformedJSON(t *testing.T) {
	if _, err := Load(strings.NewReader(`{"schema_version": 1,`)); err == nil {
		t.Fatal("malformed JSON must fail")
	}
}

func TestDigestIsStableAndPrefixed(t *testing.T) {
	a, _ := Load(strings.NewReader(minimalSnapshot))
	b, _ := Load(strings.NewReader(minimalSnapshot))
	if a.Digest() != b.Digest() || !strings.HasPrefix(a.Digest(), "sha256:") {
		t.Fatalf("digests %q %q", a.Digest(), b.Digest())
	}
}

// H-12 (f11): a snapshot is ONE JSON value. checkDepth walks every value in
// the stream and Decode read only the first, so `cat pass.json fail.json`
// judged the first snapshot and dropped the rest without a word.
func TestLoadRefusesTrailingJSONValues(t *testing.T) {
	for name, tail := range map[string]string{
		"second snapshot after a newline": "\n" + minimalSnapshot,
		"second snapshot, no separator":   minimalSnapshot,
		"object":                          " {}",
		"array":                           " []",
		"number":                          " 1",
		"string":                          ` "x"`,
		"null":                            " null",
	} {
		t.Run(name, func(t *testing.T) {
			s, err := Load(strings.NewReader(minimalSnapshot + tail))
			if err == nil || s != nil {
				t.Fatalf("Load = %v, %v; want a refusal", s, err)
			}
			if errors.Is(err, ErrSchemaMismatch) || errors.Is(err, ErrTooDeep) || errors.Is(err, ErrTooLarge) {
				t.Errorf("err %v must be a plain parse error", err)
			}
			if want := "parse snapshot: unexpected data after the snapshot (one JSON value expected)"; err.Error() != want {
				t.Errorf("err %q, want %q", err, want)
			}
		})
	}
	for name, tail := range map[string]string{"none": "", "newline": "\n", "crlf": "\r\n", "mixed whitespace": "\n\n\t  "} {
		t.Run("accepts "+name, func(t *testing.T) {
			s, err := Load(strings.NewReader(minimalSnapshot + tail))
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := s.Facts["services"]; !ok || s.Run.Host.Hostname != "web-01" {
				t.Errorf("snapshot decoded badly: %+v", s)
			}
		})
	}
}

// FuzzLoad: Load takes untrusted bytes (spec §7.2). It never panics, and an
// accepted snapshot always carries a facts tree and a supported version.
func FuzzLoad(f *testing.F) {
	f.Add([]byte(minimalSnapshot))
	f.Add([]byte(minimalSnapshot + minimalSnapshot))
	f.Add([]byte(minimalSnapshot + " 1"))
	f.Add([]byte(minimalSnapshot + "\r\n"))
	f.Add([]byte(`{"schema_version": 1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := Load(bytes.NewReader(data))
		if (s == nil) == (err == nil) {
			t.Fatalf("Load = %v, %v: exactly one of the two must be set", s, err)
		}
		if err == nil && (s.Facts == nil || s.SchemaVersion < 1 || s.SchemaVersion > SchemaVersion) {
			t.Fatalf("accepted snapshot %+v", s)
		}
	})
}
