package profile

import "testing"

func FuzzParseProfile(f *testing.F) {
	// Seeds are literals (Z-12): the site.yaml of
	// TestResolveChainIncludeExcludeParamsSeverity, a minimal profile and the
	// built-in's YAML spelling.
	f.Add([]byte("profile: site\nextends: base.yaml\ninclude: [muster.beyond.exposed_listeners_allowed]\nparams:\n  muster.beyond.exposed_listeners_allowed:\n    allowed_ports: [tcp/22, tcp/443]\n  muster.beyond.no_deleted_executables: {}\nseverity:\n  - { controls: muster.file.world_writable, level: high }\n"))
	f.Add([]byte("profile: a\ninclude: [\"muster.*\"]\n"))
	f.Add([]byte("profile: default\ninclude: [\"muster.*\"]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		file, err := Parse(data)
		if err != nil && file != nil {
			t.Fatalf("error with a file: %v", err)
		}
		// parse is Parse without the sentinel: the same verdict on the same bytes.
		inner, innerErr := parse(data)
		if (innerErr == nil) != (err == nil) || (innerErr != nil && inner != nil) {
			t.Fatalf("parse and Parse disagree: %v vs %v", innerErr, err)
		}
	})
}
