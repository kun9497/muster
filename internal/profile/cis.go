package profile

import "strings"

// CIS ties a CIS built-in to the benchmark it is built from and the hosts
// that benchmark covers (CB-10, CB-11). Benchmark is the canonical CIS index
// product; Targets are the product and its applies_to aliases, as the host
// warning names them.
type CIS struct {
	Profile   string
	Benchmark string
	Targets   []string

	ids     []string // os-release ids the benchmark covers
	version string   // the exact version_id, or "" when only the major counts
	major   string   // the first dotted component of version_id
}

var cisTable = []CIS{
	{Profile: "cis-rhel9-l1", Benchmark: "rhel9", Targets: []string{"rhel9", "alma9", "rocky9"}, ids: []string{"rhel", "rocky", "almalinux"}, major: "9"},
	{Profile: "cis-ubuntu2204-l1", Benchmark: "ubuntu2204", Targets: []string{"ubuntu2204"}, ids: []string{"ubuntu"}, version: "22.04"},
	{Profile: "cis-ubuntu2404-l1", Benchmark: "ubuntu2404", Targets: []string{"ubuntu2404"}, ids: []string{"ubuntu"}, version: "24.04"},
}

// Matches reports whether a host's os-release id and version_id (as the
// collector writes them: verbatim, empty when unreadable) are one the
// benchmark covers. CentOS Stream is not named and does not match.
func (c CIS) Matches(id, versionID string) bool {
	known := false
	for _, x := range c.ids {
		if x == id {
			known = true
		}
	}
	if !known || versionID == "" {
		return false
	}
	if c.version != "" {
		return versionID == c.version
	}
	major, _, _ := strings.Cut(versionID, ".")
	return major == c.major
}

// CISBenchmark returns the CIS entry of a built-in name; default, the alias
// and anything else are not found.
func CISBenchmark(name string) (CIS, bool) {
	for _, c := range cisTable {
		if c.Profile == name {
			c.Targets = append([]string(nil), c.Targets...)
			return c, true
		}
	}
	return CIS{}, false
}

// CISRoot returns the CIS entry of a resolved chain whose root is a CIS
// built-in (Resolved.Chain, root first): a file extending one is that
// built-in's.
func CISRoot(chain []string) (CIS, bool) {
	if len(chain) == 0 {
		return CIS{}, false
	}
	name, ok := strings.CutPrefix(chain[0], "builtin:")
	if !ok {
		return CIS{}, false
	}
	return CISBenchmark(name)
}
