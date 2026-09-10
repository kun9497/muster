package facts

import (
	"encoding/json"
	"os"
	"testing"
)

// capabilityMatrixPath is the committed matrix CI asserts against: the fact
// keys whose status is decided by the runner's capability rather than by the
// host's configuration (spec line 466, ruling M-18).
const capabilityMatrixPath = "../../docs/reference/capability-matrix.json"

// M-18/M-34: the matrix is only worth a CI step if every key in it is a
// registered key CI can actually address by its dotted path. A setting's
// envelope has no single .status — its runtime and persisted sides carry one
// each — so a setting key would make the jq expression read null and the step
// would pass on nothing. The two status words are the whole vocabulary: a
// third would name a status no jq step tests for.
func TestCapabilityMatrixNamesRegisteredKeys(t *testing.T) {
	raw, err := os.ReadFile(capabilityMatrixPath)
	if err != nil {
		t.Fatal(err)
	}
	var matrix map[string]map[string][]string
	if err := json.Unmarshal(raw, &matrix); err != nil {
		t.Fatalf("%s: %v", capabilityMatrixPath, err)
	}
	reg, err := LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	families := map[string]bool{"nonroot": false, "no-systemd": false}
	statuses := map[string]bool{"denied": true, "unsupported": true}
	for family, byStatus := range matrix {
		seen, known := families[family]
		if !known {
			t.Errorf("%s: unknown capability family %q", capabilityMatrixPath, family)
			continue
		}
		if seen {
			t.Errorf("%s: family %q appears twice", capabilityMatrixPath, family)
		}
		families[family] = true
		for status, keys := range byStatus {
			if !statuses[status] {
				t.Errorf("%s: %s names status %q; the vocabulary is denied and unsupported", capabilityMatrixPath, family, status)
			}
			if len(keys) == 0 {
				t.Errorf("%s: %s.%s is empty, so the CI step asserts nothing", capabilityMatrixPath, family, status)
			}
			for _, key := range keys {
				e, ok := reg.Lookup(key)
				if !ok {
					t.Errorf("%s: %s.%s names %q, which is not a registered fact key", capabilityMatrixPath, family, status, key)
					continue
				}
				// M-34: only a plain envelope answers `.status`; a setting
				// splits into sides and the jq step would read null.
				if family == "nonroot" && reg.IsSetting(e) {
					t.Errorf("%s: nonroot names the setting %q (type %s); a setting's sides carry the status, not the key", capabilityMatrixPath, key, e.Type)
				}
			}
		}
	}
	for family, seen := range families {
		if !seen {
			t.Errorf("%s: family %q is missing", capabilityMatrixPath, family)
		}
	}
}
