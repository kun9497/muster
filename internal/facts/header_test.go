package facts

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// LoadHeader reads the provenance of a snapshot a newer binary wrote, so the
// listing can show it; the schema classification is the caller's (RL-16).
func TestLoadHeaderReadsRunAndSchemaWithoutComparing(t *testing.T) {
	doc := `{"schema_version": 7, "run": {"muster_version": "2027.01.01", "collected_at": "2026-09-02T06:00:00Z", "host": {"hostname": "web_01_prod"}}, "facts": {"new.shape": [1, 2]}}`
	h, err := LoadHeader(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("LoadHeader: %v", err)
	}
	if h.SchemaVersion != 7 || h.Run.CollectedAt != "2026-09-02T06:00:00Z" || h.Run.Host.Hostname != "web_01_prod" || h.Run.MusterVersion != "2027.01.01" {
		t.Errorf("header = %+v", h)
	}

	if _, err := LoadHeader(strings.NewReader(`{"schema_version": 0, "run": {}}`)); !errors.Is(err, ErrSchemaMismatch) {
		t.Errorf("schema_version 0: err = %v, want ErrSchemaMismatch", err)
	}
	if _, err := LoadHeader(strings.NewReader(`{}`)); !errors.Is(err, ErrSchemaMismatch) {
		t.Errorf("{}: err = %v, want ErrSchemaMismatch", err)
	}
	big := bytes.Repeat([]byte(" "), MaxSnapshotBytes+1)
	if _, err := LoadHeader(bytes.NewReader(big)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversize: err = %v, want ErrTooLarge", err)
	}
	if _, err := LoadHeader(strings.NewReader(`{"schema_version": 1, "run": {}} "x"`)); !errors.Is(err, ErrTrailingData) {
		t.Errorf("trailing: err = %v, want ErrTrailingData", err)
	}
}
