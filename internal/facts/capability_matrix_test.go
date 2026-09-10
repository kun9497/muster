package facts

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// capabilityMatrixPath is the committed matrix CI asserts against: the fact
// keys whose status is decided by the runner's capability rather than by the
// host's configuration (spec line 466, ruling M-18).
const capabilityMatrixPath = "../../docs/reference/capability-matrix.json"

// capabilityFamilies are the two runner capabilities the matrix describes, and
// capabilityStatuses the two words the CI steps test for. A third of either
// would name something no step asserts.
var (
	capabilityFamilies = []string{"nonroot", "no-systemd"}
	capabilityStatuses = []string{"denied", "unsupported"}
)

// M-18/M-34: the matrix is only worth a CI step if every key in it is a
// registered key CI can actually address by its dotted path. A setting's
// envelope has no single .status - its runtime and persisted sides carry one
// each - so a setting key would make the jq expression read null and the step
// would pass on nothing. A files.*.{mode,uid,gid} leaf is the other trap:
// those look root-only but are answered by a stat, which muster opens with
// O_PATH and which needs no read permission, so they are not denied to an
// unprivileged run at all.
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

	var problems []string
	report := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}
	for _, family := range sortedMapKeys(matrix) {
		if !contains(capabilityFamilies, family) {
			report("unknown capability family %q; the families are %s", family, strings.Join(capabilityFamilies, " and "))
			continue
		}
		byStatus := matrix[family]
		for _, status := range sortedStatusKeys(byStatus) {
			if !contains(capabilityStatuses, status) {
				report("%s names status %q; the vocabulary is %s", family, status, strings.Join(capabilityStatuses, " and "))
			}
			keys := byStatus[status]
			if len(keys) == 0 {
				report("%s.%s is empty, so the CI step asserts nothing", family, status)
			}
			for _, key := range keys {
				e, ok := reg.Lookup(key)
				if !ok {
					report("%s.%s names %q, which is not a registered fact key", family, status, key)
					continue
				}
				// Every family: only a plain envelope answers `.status`; a
				// setting splits into sides and the jq step reads null.
				if reg.IsSetting(e) {
					report("%s names the setting %q (type %s); a setting's sides carry the status, not the key", family, key, e.Type)
				}
				// M-34, the nonroot half: a stat-only leaf is not denied to an
				// unprivileged run, because the stat opens with O_PATH.
				if family == "nonroot" && isStatLeaf(key) {
					report("nonroot names %q; a mode, uid or gid leaf comes from a stat opened with O_PATH, which needs no read permission and is not denied without root", key)
				}
			}
		}
	}
	for _, family := range capabilityFamilies {
		if _, ok := matrix[family]; !ok {
			report("family %q is missing", family)
		}
	}

	sort.Strings(problems)
	for _, p := range problems {
		t.Errorf("%s: %s", capabilityMatrixPath, p)
	}
}

func isStatLeaf(key string) bool {
	last := key[strings.LastIndex(key, ".")+1:]
	return last == "mode" || last == "uid" || last == "gid"
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func sortedMapKeys(m map[string]map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedStatusKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
