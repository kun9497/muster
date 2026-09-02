package facts

import (
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
