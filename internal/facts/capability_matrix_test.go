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

// capabilityFamilies are the runner capabilities the matrix describes, and
// capabilityStatuses the two words the CI steps test for. One more of either
// would name something no step asserts, so the list grows only when a step
// does: "container" arrived with the deep walk, whose finding lists are
// unsupported on a root layer the walk does not enter.
var (
	capabilityFamilies = []string{"nonroot", "no-systemd", "container"}
	capabilityStatuses = []string{"denied", "unsupported"}
)

// M-18/M-34: the matrix is only worth a CI step if every key in it is a
// registered key CI can actually address by its dotted path. A setting is
// addressable too, since K-17: its envelope has no .status of its own - the
// runtime, persisted and effective sides carry one each - so the CI steps
// read `(.status // .effective.status)`, and the effective side is the right
// one to read only for a setting the registry judges there. A setting with
// any other default_on would be checked on a side no control reads, so it is
// rejected here rather than silently asserted against the wrong status.
// A files.*.{mode,uid,gid} leaf is the other trap: those look root-only but
// are answered by a stat, which muster opens with O_PATH and which needs no
// read permission, so they are not denied to an unprivileged run at all.
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
	for _, p := range capabilityMatrixProblems(reg, matrix) {
		t.Errorf("%s: %s", capabilityMatrixPath, p)
	}
}

// K-17: the setting rule above is a live rule, not a comment. Eight registered
// settings are judged on `both` sides rather than on the effective one, and a
// matrix that named one of them would have the CI step read a status the
// control does not use. This feeds the checker such a matrix and demands the
// complaint, so deleting the rule goes red here rather than in six months on
// somebody's runner.
func TestCapabilityMatrixRejectsASettingJudgedOffTheEffectiveSide(t *testing.T) {
	reg, err := LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	var key string
	for _, e := range reg.Keys {
		if reg.IsSetting(e) && e.DefaultOn != "effective" {
			key = e.Key
			break
		}
	}
	if key == "" {
		t.Skip("no registered setting is judged off the effective side, so the rule has nothing to reject here")
	}
	problems := capabilityMatrixProblems(reg, map[string]map[string][]string{
		"nonroot":    {"denied": {key}},
		"no-systemd": {"unsupported": {"services.ssh.installed"}},
		"container":  {"unsupported": {"kernel.modules"}},
	})
	found := false
	for _, p := range problems {
		if strings.Contains(p, key) && strings.Contains(p, "effective.status") {
			found = true
		}
	}
	if !found {
		t.Errorf("a matrix naming %s (default_on is not effective) must be reported; problems were %v", key, problems)
	}
	// The same matrix with a setting judged on the effective side is fine:
	// the five 0600 sysctls of B-3 are exactly that, and a rule that rejected
	// every setting would put them back out of reach of the CI step.
	if p := capabilityMatrixProblems(reg, map[string]map[string][]string{
		"nonroot":    {"denied": {"kernel.sysctl.protected_fifos"}},
		"no-systemd": {"unsupported": {"services.ssh.installed"}},
		"container":  {"unsupported": {"kernel.modules"}},
	}); len(p) != 0 {
		t.Errorf("a setting judged on the effective side is addressable through .effective.status: %v", p)
	}
}

// capabilityMatrixProblems is the checker itself, over a decoded matrix, so
// both the committed file and a constructed one can be put through it.
func capabilityMatrixProblems(reg *Registry, matrix map[string]map[string][]string) []string {
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
				// Every family: a plain envelope answers `.status` and a
				// setting answers `.effective.status`, which is the fallback
				// the CI jq takes - but only a setting judged on the
				// effective side has its answer there.
				if reg.IsSetting(e) && e.DefaultOn != "effective" {
					report("%s names the setting %q (type %s, default_on %q); the CI step falls back to .effective.status, which is not the side this key is judged on", family, key, e.Type, e.DefaultOn)
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
	return problems
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
