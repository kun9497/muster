package facts

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

type fieldDesc struct {
	JSON string `json:"json"`
	Type string `json:"type"`
}

type schemaDesc struct {
	SchemaVersion int                    `json:"schema_version"`
	Run           map[string][]fieldDesc `json:"run"` // struct name → fields
	Keys          []Entry                `json:"keys"`
}

func describe(t reflect.Type, into map[string][]fieldDesc) {
	if t.Kind() == reflect.Ptr || t.Kind() == reflect.Slice {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || into[t.Name()] != nil {
		return
	}
	var fields []fieldDesc
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		fields = append(fields, fieldDesc{JSON: tag, Type: f.Type.String()})
		describe(f.Type, into)
	}
	into[t.Name()] = fields
}

// The golden changes whenever the run header or the registry changes shape,
// which forces the author through the versioning rule of spec §5.7.
func TestFactsSchemaGolden(t *testing.T) {
	reg, err := LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	desc := schemaDesc{SchemaVersion: SchemaVersion, Run: map[string][]fieldDesc{}, Keys: reg.Keys}
	describe(reflect.TypeOf(Run{}), desc.Run)
	got, _ := json.MarshalIndent(desc, "", "  ")
	got = append(got, '\n')
	path := filepath.Join("testdata", "facts-schema.golden.json")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("facts schema changed; if intended, bump SchemaVersion or add `since`, then run: go test ./internal/facts -run TestFactsSchemaGolden -update\n--- got ---\n%s", got)
	}
}
